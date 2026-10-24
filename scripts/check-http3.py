#!/usr/bin/env python3
"""Verify HTTP/3 reverse capture using mitmproxy's bundled aioquic client."""
import http.server,json,os,ssl,subprocess,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def prepare_client_support():
    import base64,hashlib,urllib.request
    checks={
        'asyncio/client.py':'f6184a451edcb46c55a24dac1001e57d66d2c3b2a3c9fe823117e8f0d442c87f',
        'asyncio/protocol.py':'67b69f8bab1057bd878b84a6c55ab49ab028644be6692a3cb9045890c913563b',
        'asyncio/server.py':'b976cd46b1351a53cdfd66f2ce04d435ce2bd75c87ee7161ddd8bd1014206cf4',
        'quic/retry.py':'54a8301fae4d664545eea2cdc63892332b72a1d598b0a597ab0f184af2af72ab',
        'LICENSE':'8d7e3143cf6e8baf4e7f0ee5fc0ac5927c9e0bcdc4e8c8329fc3dfe74e3d1cf5'}
    base=ROOT/'.runtime/aioquic-test';downloads=0
    for name,digest in checks.items():
        path=base/name if name=='LICENSE' else base/'aioquic'/name
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==digest:continue
        upstream='LICENSE' if name=='LICENSE' else 'src/aioquic/'+name
        request=urllib.request.Request('https://api.github.com/repos/aiortc/aioquic/contents/'+upstream+'?ref=1.2.0',headers={'Accept':'application/vnd.github+json','User-Agent':'MOP-protocol-check'})
        with urllib.request.urlopen(request,timeout=10) as response:metadata=json.loads(response.read(131072))
        data=base64.b64decode(metadata['content'])
        if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Test support checksum mismatch')
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);downloads+=1
    return downloads


def main():
    downloads=prepare_client_support()
    work=ROOT/'artifacts'/('http3-check-'+str(int(time.time())));work.mkdir(mode=0o700)
    ca=ROOT/'.runtime/network/ca'
    subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(work/'key.pem'),'-out',str(work/'request.pem'),'-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (work/'extensions').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n')
    subprocess.run(['openssl','x509','-req','-in',str(work/'request.pem'),'-CA',str(ca/'mitmproxy-ca-cert.pem'),'-CAkey',str(ca/'mitmproxy-ca.pem'),'-set_serial',str(int(time.time())),'-days','1','-extfile',str(work/'extensions'),'-out',str(work/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'{"message":"hello through HTTP3"}';self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(work/'cert.pem',work/'key.pem');server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    client_source=r'''import asyncio,base64,json,os
from pathlib import Path
from mitmproxy import ctx
import aioquic
import types,sys
namespace=types.ModuleType('aioquic.asyncio')
namespace.__path__=[str(Path(os.environ['MOP_CHECK_ROOT'])/'.runtime/aioquic-test/aioquic/asyncio')]
sys.modules['aioquic.asyncio']=namespace
import aioquic.quic
aioquic.quic.__path__.append(str(Path(os.environ['MOP_CHECK_ROOT'])/'.runtime/aioquic-test/aioquic/quic'))
from aioquic.asyncio.client import connect
from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection,H3_ALPN
from aioquic.h3.events import DataReceived,HeadersReceived
class Client(QuicConnectionProtocol):
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.http=H3Connection(self._quic);self.future=None;self.body=bytearray();self.headers=[]
 def quic_event_received(self,event):
  for item in self.http.handle_event(event):
   if isinstance(item,HeadersReceived):self.headers.extend(item.headers)
   if isinstance(item,DataReceived):self.body.extend(item.data)
   if isinstance(item,(HeadersReceived,DataReceived)) and item.stream_ended and self.future and not self.future.done():self.future.set_result(bytes(self.body))
 async def request(self,auth):
  self.future=asyncio.get_running_loop().create_future();stream=self._quic.get_next_available_stream_id()
  self.http.send_headers(stream,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'localhost:18940'),(b':path',b'/mop-http3'),(b'proxy-authorization',auth)],end_stream=True);self.transmit()
  return await asyncio.wait_for(self.future,10)
class Server(QuicConnectionProtocol):
 def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.http=H3Connection(self._quic)
 def quic_event_received(self,event):
  for item in self.http.handle_event(event):
   if isinstance(item,HeadersReceived):
    body=b'{"message":"hello through HTTP3"}'
    self.http.send_headers(item.stream_id,[(b':status',b'200'),(b'content-type',b'application/json'),(b'content-length',str(len(body)).encode())])
    self.http.send_data(item.stream_id,body,end_stream=True);self.transmit()
class Check:
 async def running(self):
  asyncio.create_task(self.run())
 async def run(self):
  result={};server=None
  try:
   root=Path(os.environ['MOP_CHECK_ROOT']);config=json.loads((root/'.runtime/network/config.json').read_text())
   auth=b'Basic '+base64.b64encode((config['username']+':'+config['password']).encode())
   configuration=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,server_name='localhost')
   configuration.load_verify_locations(cafile=str(root/'.runtime/network/ca-bundle.pem'))
   server_config=QuicConfiguration(is_client=False,alpn_protocols=H3_ALPN)
   server_config.load_cert_chain(os.environ['MOP_CHECK_CERT'],os.environ['MOP_CHECK_KEY'])
   server=await serve('127.0.0.1',18941,configuration=server_config,create_protocol=Server)
   async with connect('127.0.0.1',18940,configuration=configuration,create_protocol=Client) as client:
    body=await client.request(auth);result={'body':json.loads(body),'http3':True}
  except Exception as e:result={'error':type(e).__name__+': '+str(e)}
  finally:
   if server:server.close()
   Path(os.environ['MOP_CHECK_RESULT']).write_text(json.dumps(result));ctx.master.shutdown()
addons=[Check()]
'''
    (work/'client.py').write_text(client_source)
    reverse=None;watch=None
    try:
        with (work/'reverse.log').open('w') as log:
            reverse=subprocess.Popen([str(ROOT/'scripts/mop-network'),'reverse','--upstream','https://127.0.0.1:18941'],stdout=log,stderr=subprocess.STDOUT)
        time.sleep(3)
        with (work/'watch.log').open('w') as log:
            watch=subprocess.Popen([str(ROOT/'scripts/mop'),'-b','--duration','30','-p',str(os.getpid()),'--no-tetragon','--log',str(work/'audit.jsonl')],stdout=log,stderr=subprocess.STDOUT)
        time.sleep(2)
        env=os.environ.copy();env.update(MOP_CHECK_ROOT=str(ROOT),MOP_CHECK_RESULT=str(work/'client-result.json'),MOP_CHECK_CERT=str(work/'cert.pem'),MOP_CHECK_KEY=str(work/'key.pem'))
        with (work/'client.log').open('w') as log:
            result=subprocess.run([str(ROOT/'.runtime/mitmproxy-12.2.3/mitmdump'),'-q','--mode','regular@127.0.0.1:0','--set','confdir='+str(work/'client-ca'),'-s',str(work/'client.py')],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=25)
        time.sleep(4)
    finally:
        for proc in (watch,reverse):
            if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=15)
        server.shutdown();server.server_close()
    rows=[]
    for line in (work/'audit.jsonl').read_text().splitlines():
        row=json.loads(line)
        if row.get('event',{}).get('source')=='network-proxy' and '/mop-http3' in json.dumps(row['event']['metadata']['evidence']):rows.append(row)
    client=json.loads((work/'client-result.json').read_text()) if (work/'client-result.json').exists() else {}
    report={'directory':str(work),'client':client,'external_model_calls':0,'test_support_downloads':downloads,'guard_events':[{'kind':r['event']['metadata']['kind'],'evidence':r['event']['metadata']['evidence'],'category':r['verdict']['category']} for r in rows]}
    report['verified_at']=time.time();report['all_verified']=client.get('body')=={'message':'hello through HTTP3'} and len(rows)>=2 and all(r['verdict']['category']!='unknown' for r in rows)
    (ROOT/'.runtime/network/validation-http3.json').write_text(json.dumps(report,indent=2))
    (work/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
    if client.get('body')!={'message':'hello through HTTP3'} or len(rows)<2:raise SystemExit(1)

if __name__=='__main__':main()
