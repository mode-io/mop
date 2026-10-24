#!/usr/bin/env python3
"""Verify the installed service with owned stdout and loopback HTTP/1 TLS clients."""
import argparse
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
STARTED=time.time()


def records(path):
    try:
        with path.open('rb') as stream:
            stream.seek(max(0,path.stat().st_size-1024*1024))
            data=stream.read(1024*1024)
        rows=[]
        for line in data.splitlines():
            try:rows.append(json.loads(line))
            except (ValueError,UnicodeDecodeError):pass
        return rows
    except OSError:return []


def wait_for(path,pid,kind,timeout=4):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        found=[r for r in records(path) if r.get('metadata',{}).get('observed_pid')==pid and r['metadata'].get('kind')==kind and r['metadata'].get('captured_at',0)>=STARTED]
        if found:return found
        time.sleep(.2)
    return []


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True);args=parser.parse_args()
    events=Path('/var/log/mop-content')/str(os.getuid())/'events.jsonl'
    result={'stdout':False,'python_tls_request':False,'python_tls_response':False,
            'curl_tls_request':False,'curl_tls_response':False,'external_requests':0}
    for _ in range(5):
        child=subprocess.Popen([sys.executable,'-c','print("hello",flush=True)'],stdout=subprocess.DEVNULL)
        child.wait(timeout=4)
        found=wait_for(events,child.pid,'stdio',timeout=2)
        if any(r['metadata']['evidence'].get('text')=='hello\n' for r in found):result['stdout']=True;break
    with tempfile.TemporaryDirectory(dir=args.work,prefix='installed-tls-') as tmp:
        d=Path(tmp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(d/'key'),
            '-out',str(d/'cert'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ('/mop-install-chunked','/mop-install-sse'):
                    streaming=self.path.endswith('sse')
                    self.send_response(200)
                    self.send_header('Content-Type','text/event-stream' if streaming else 'application/json')
                    self.send_header('Transfer-Encoding','chunked');self.end_headers()
                    chunks=[b'data: {"message":"hello"}\n\n',b'data: [DONE]\n\n'] if streaming else [b'{"message":',b'"hello"}']
                    for chunk in chunks:
                        self.wfile.write(hex(len(chunk))[2:].encode()+b'\r\n'+chunk+b'\r\n');self.wfile.flush()
                    self.wfile.write(b'0\r\n\r\n');self.wfile.flush();return
                body=b'{"message":"hello"}';self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(d/'cert',d/'key')
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            url=f'https://localhost:{server.server_port}/mop-install-check'
            code='import ssl,urllib.request,sys,time; c=ssl.create_default_context(cafile=sys.argv[1]); o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); assert o.open(sys.argv[2],timeout=4).read()==b\'{"message":"hello"}\'; time.sleep(.5)'
            for name,command in [('python',[sys.executable,'-c',code,str(d/'cert'),url]),
                                 ('curl',['/usr/bin/curl','--noproxy','*','--http1.1','--silent','--show-error','--max-time','4','--cacert',str(d/'cert'),url])]:
                child=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                child.wait(timeout=6)
                requests=wait_for(events,child.pid,'http_request')
                responses=wait_for(events,child.pid,'http_response')
                result[name+'_tls_request']=any(r['metadata']['evidence'].get('path')=='/mop-install-check' for r in requests)
                result[name+'_tls_response']=any(r['metadata']['evidence'].get('body')=={'message':'hello'} for r in responses)
                result[name+'_client_exit']=child.returncode
            for path,kind in [('/mop-install-chunked','http_response'),('/mop-install-sse','http_response_event')]:
                target=f'https://localhost:{server.server_port}'+path
                code='import ssl,urllib.request,sys,time; o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=sys.argv[1]))); o.open(sys.argv[2],timeout=4).read(); time.sleep(.5)'
                child=subprocess.Popen([sys.executable,'-c',code,str(d/'cert'),target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                child.wait(timeout=6)
                rows=wait_for(events,child.pid,kind)
                result['chunked_response' if path.endswith('chunked') else 'sse_response']=any(r['metadata']['evidence'].get('body')=={'message':'hello'} for r in rows)
                result.setdefault('request_response_linked',True)
                result['request_response_linked'] &= any(r['metadata']['evidence'].get('original_request',{}).get('path')==path for r in rows)
                if path.endswith('sse'):result['sse_complete']=bool(wait_for(events,child.pid,'http_response_end'))
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
