"""Explicit loopback JSON proxy with bounded, asynchronous content classification."""
import asyncio
import concurrent.futures
import ipaddress
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .classification import NoRedirect
from .content import text_evidence
from .core import Event
from .proxy_review import exchange_units, gap_event
from .decision_units import DecisionBudgetError

ROUTES = {'/plugins/vllm-jev/choice', '/plugins/vllm-jev/batch',
          '/v1/chat/completions', '/v1/completions'}
MAX_BODY = 1024 * 1024


def loopback_url(value):
    parsed=urllib.parse.urlsplit(value)
    try: local=ipaddress.ip_address(parsed.hostname).is_loopback
    except (ValueError,TypeError): local=parsed.hostname=='localhost'
    if not local or parsed.scheme!='http' or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('proxy upstream must be a loopback HTTP origin without credentials or path')
    return parsed.port or 80


class BoundedServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(16)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b'HTTP/1.0 503 Busy\r\nContent-Length: 0\r\n\r\n')
            except OSError:pass
            self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


def make_server(engine,loop,upstream,port,decision_tokens=2048):
    if not 512<=decision_tokens<=4096:raise ValueError('decision token budget must be in 512..4096')
    if not 1<=port<=65535:raise ValueError('listen port must be 1..65535')
    if loopback_url(upstream)==port:raise ValueError('proxy cannot forward to itself')
    transport=getattr(engine.provider,'transport',engine.provider)
    review_url=urllib.parse.urlsplit(getattr(transport,'base_url','http://127.0.0.1:18936'))
    if (review_url.port or 80)==port:
        raise ValueError('classifier endpoint must bypass the capture proxy')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    review_gaps=deque(maxlen=128)

    def submit(event):
        future=concurrent.futures.Future()
        def on_loop():
            if not future.set_running_or_notify_cancel():return
            try:
                accepted=engine.submit(event) if engine.state=='running' else False
                future.set_result(accepted)
            except Exception as error:future.set_exception(error)
        loop.call_soon_threadsafe(on_loop)
        try:return future.result(timeout=2)
        except (concurrent.futures.TimeoutError,RuntimeError):future.cancel();return False

    def reviews():
        async def snapshot():
            rows=[]
            for row in engine.recent:
                event=row['event']
                if event['source']!='http-proxy':continue
                m=event['metadata']
                rows.append({'request_id':m.get('operation_id',m.get('request_id')),
                    'kind':m.get('kind',event['operation']), 'part':m.get('part'),
                    'parts':m.get('parts'), 'verdict':row['verdict'],
                    'input':m})
            return {'mode':'observation_only', 'history_is_bounded':True,
                    'reviews':rows, 'review_gaps':list(review_gaps), 'stats':dict(engine.stats)}
        return asyncio.run_coroutine_threadsafe(snapshot(),loop).result(timeout=2)

    def capture(request_id,route,raw,body,status,error):
        try:
            units=exchange_units(transport,request_id,route,upstream,raw,body,status,error,decision_tokens)
        except (DecisionBudgetError,ValueError,RecursionError) as failure:
            gap=gap_event(request_id,route,raw,type(failure).__name__+': '+str(failure)[:160]).metadata
            def report_gap():
                engine.stats.update(proxy_review_gaps=engine.stats.get('proxy_review_gaps',0)+1)
                review_gaps.append(gap)
            loop.call_soon_threadsafe(report_gap)
            units=[]
        for event in units:
            if not submit(event):
                loop.call_soon_threadsafe(lambda: engine.stats.update(proxy_review_rejected=engine.stats.get('proxy_review_rejected',0)+1))

    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def setup(self):
            super().setup();self.connection.settimeout(10)
        def log_message(self,*args):pass
        def send_bytes(self,status,body,kind='application/json'):
            self.send_response(status)
            self.send_header('Content-Type',kind)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Connection','close')
            self.end_headers();self.wfile.write(body)
        def reject(self,status,message):
            self.send_bytes(status,json.dumps({'error':message}).encode())
        def do_GET(self):
            if self.path=='/health':self.send_bytes(200,b'{"service":"mop-content-proxy"}')
            elif self.path=='/mop/reviews':
                try:self.send_bytes(200,json.dumps(reviews()).encode())
                except (TimeoutError,RuntimeError):self.reject(503,'review status unavailable')
            else:self.reject(404,'unsupported route')
        def do_POST(self):
            if self.path not in ROUTES:self.reject(404,'unsupported route');return
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):
                self.reject(400,'one Content-Length and unencoded JSON are required');return
            try:length=int(lengths[0])
            except ValueError:self.reject(400,'invalid Content-Length');return
            if not 0<length<=MAX_BODY:self.reject(413,'request body limit is 1 MiB');return
            try:
                raw=self.rfile.read(length)
                if len(raw)!=length:raise ValueError()
                parsed=json.loads(raw)
                if not isinstance(parsed,dict):raise ValueError()
            except (ValueError,OSError,RecursionError):self.reject(400,'invalid JSON body');return
            request_id=uuid.uuid4().hex;started=time.monotonic()
            headers={'Content-Type':'application/json','Accept-Encoding':'identity'}
            # Credentials are forwarded but never added to model evidence or logs.
            if self.headers.get('Authorization'):headers['Authorization']=self.headers['Authorization']
            request=urllib.request.Request(upstream.rstrip('/')+self.path,raw,headers)
            error=None;sent=False;body=b'';status=502
            try:
                try:response=opener.open(request,timeout=15)
                except urllib.error.HTTPError as failure:response=failure
                with response:
                    status=response.code;kind=response.headers.get('Content-Type','application/json')
                    if 'text/event-stream' in kind:
                        self.send_response(status)
                        self.send_header('Content-Type',kind)
                        self.send_header('Connection','close')
                        self.send_header('X-MOP-Request-ID',request_id)
                        self.end_headers();sent=True
                        chunks=[];size=0
                        try:
                            while True:
                                if time.monotonic()-started>120:raise TimeoutError('stream duration limit')
                                chunk=response.read1(min(8192,MAX_BODY-size+1))
                                if not chunk:break
                                size+=len(chunk)
                                if size>MAX_BODY:raise ValueError('stream capture size limit')
                                chunks.append(chunk)
                                self.wfile.write(chunk);self.wfile.flush()
                        finally:body=b''.join(chunks)
                    else:
                        body=response.read(MAX_BODY+1)
                        if len(body)>MAX_BODY:raise ValueError('response size limit')
            except Exception as failure:
                error=type(failure).__name__
                if not sent:
                    status,kind,body=502,'application/json',b'{"error":"upstream unavailable or response exceeds limit"}'
            try:capture(request_id,self.path,raw,body,status,error)
            except (RuntimeError,concurrent.futures.CancelledError):pass
            try:
                if not sent:self.send_bytes(status,body,kind)
            except OSError:pass
    return BoundedServer(('127.0.0.1',port),Handler)


async def run_proxy(engine,upstream,port,duration=None,decision_tokens=2048):
    server=make_server(engine,asyncio.get_running_loop(),upstream,port,decision_tokens)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1},daemon=True)
    thread.start()
    print('MOP content proxy listening on http://127.0.0.1:%d; classifier traffic bypasses this listener.'%port,flush=True)
    try:
        if duration is None:await asyncio.Event().wait()
        else:await asyncio.sleep(duration)
    finally:
        await asyncio.to_thread(server.shutdown)
        await asyncio.to_thread(server.server_close)
        await asyncio.to_thread(thread.join,2)
