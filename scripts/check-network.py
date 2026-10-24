#!/usr/bin/env python3
"""Verify routed protocols with real loopback servers and optional live API traffic."""
import argparse
import base64
import concurrent.futures
import gzip
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true');args=parser.parse_args()
    work=ROOT/'artifacts'/('network-check-'+str(int(time.time())));work.mkdir(mode=0o700)
    config=json.loads((ROOT/'.runtime/network/config.json').read_text())
    password=config['password'];proxy='http://'+config['username']+':'+password+'@127.0.0.1:18938'
    ca=ROOT/'.runtime/network/ca';bundle=ROOT/'.runtime/network/ca-bundle.pem'
    subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(work/'key.pem'),'-out',str(work/'request.pem'),'-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (work/'extensions').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n')
    subprocess.run(['openssl','x509','-req','-in',str(work/'request.pem'),'-CA',str(ca/'mitmproxy-ca-cert.pem'),'-CAkey',str(ca/'mitmproxy-ca.pem'),'-set_serial',str(int(time.time())),'-days','1','-extfile',str(work/'extensions'),'-out',str(work/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    results={};start=time.time();external=0
    logfile=(work/'watch.log').open('w')
    watcher=subprocess.Popen([str(ROOT/'scripts/mop'),'-b','-d','0.5','--duration','100','-p',str(os.getpid()),'--no-tetragon','--log',str(work/'audit.jsonl'),'--prompt-log',str(work/'inputs.jsonl')],stdout=logfile,stderr=subprocess.STDOUT)
    time.sleep(3)
    os.environ.update(HTTP_PROXY=proxy,HTTPS_PROXY=proxy,http_proxy=proxy,https_proxy=proxy,grpc_proxy=proxy,
        NO_PROXY='',no_proxy='',no_grpc_proxy='',SSL_CERT_FILE=str(bundle),REQUESTS_CA_BUNDLE=str(bundle))
    def check(name,fn):
        try:results[name]={'client_ok':True,'result':fn()}
        except Exception as e:results[name]={'client_ok':False,'error':(type(e).__name__+': '+str(e)).replace(password,'[REDACTED]')[:400]}
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(work/'cert.pem',work/'key.pem')
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=gzip.compress(b'{"message":"hello compressed response"}')
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Encoding','gzip')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.socket=ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        import httpx
        check('https_gzip',lambda:httpx.get(f'https://localhost:{server.server_port}/mop-gzip',timeout=10).json())
        from websockets.sync.server import serve
        from websockets.sync.client import connect
        def echo(connection):
            for message in connection:connection.send(message)
        with serve(echo,'127.0.0.1',0,ssl=ctx) as ws:
            thread=threading.Thread(target=ws.serve_forever,daemon=True);thread.start()
            def websocket():
                with connect(f'wss://127.0.0.1:{ws.socket.getsockname()[1]}/mop-websocket',ssl=ssl.create_default_context(cafile=str(bundle)),proxy=proxy,open_timeout=8) as client:
                    client.send('hello through WebSocket');return client.recv(timeout=8)
            check('wss',websocket);ws.shutdown();thread.join(timeout=2)
        import grpc
        rpc=grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=2))
        rpc.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('mop.Echo',{'Say':grpc.unary_unary_rpc_method_handler(lambda data,context:data,request_deserializer=lambda data:data,response_serializer=lambda data:data)}),))
        port=rpc.add_secure_port('127.0.0.1:0',grpc.ssl_server_credentials((( (work/'key.pem').read_bytes(),(work/'cert.pem').read_bytes()),)))
        rpc.start()
        def grpc_call():
            with grpc.secure_channel('localhost:'+str(port),grpc.ssl_channel_credentials(root_certificates=bundle.read_bytes())) as channel:
                value=channel.unary_unary('/mop.Echo/Say')(b'\x0a\x05hello',timeout=10)
                assert value==b'\x0a\x05hello';return base64.b64encode(value).decode()
        check('grpc_http2',grpc_call);rpc.stop(0).wait(timeout=3)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        def echo_tcp():
            connection,_=listener.accept()
            with connection:connection.sendall(connection.recv(1024))
        threading.Thread(target=echo_tcp,daemon=True).start()
        def socks():
            with socket.create_connection(('127.0.0.1',18939),timeout=8) as client:
                client.sendall(b'\x05\x01\x02');assert client.recv(2)==b'\x05\x02'
                user=config['username'].encode();secret=password.encode()
                client.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(secret)])+secret);assert client.recv(2)==b'\x01\x00'
                client.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',listener.getsockname()[1]))
                reply=client.recv(10);assert reply[1]==0
                client.sendall(b'hello through TCP with enough bytes for protocol detection.\n');return client.recv(200).decode()
        check('socks_tcp',socks);listener.close()
        def dns():
            packet=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x09localhost\x00\x00\x01\x00\x01'
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(8);client.sendto(packet,('127.0.0.1',18953));reply=client.recv(4096)
                assert reply[:2]==b'\x12\x34';return {'rcode':reply[3]&15,'answer_count':int.from_bytes(reply[6:8],'big')}
        check('dns',dns)
        if args.live:
            import openai
            def sdk():
                client=openai.OpenAI(api_key=os.environ['OPENAI_API_KEY'],base_url=os.environ['OPENAI_BASE_URL'],max_retries=0,timeout=25)
                try:
                    stream=client.chat.completions.create(model='deepseek-chat',messages=[{'role':'user','content':'What does CPU stand for? Answer in one short sentence.'}],stream=True,max_tokens=32)
                    with stream:return ''.join(chunk.choices[0].delta.content or '' for chunk in stream if chunk.choices)
                finally:client.close()
            external+=1;check('openai_sdk_sse',sdk)
        time.sleep(5)
    finally:
        server.shutdown();server.server_close();watcher.terminate();watcher.wait(timeout=15);logfile.close()
    records=[]
    for line in (work/'audit.jsonl').read_text().splitlines():
        row=json.loads(line)
        if row.get('event',{}).get('source')=='network-proxy':records.append(row)
    (work/'guard-events.json').write_text(json.dumps(records,indent=2))
    summary={}
    for row in records:
        kind=row['event']['metadata']['kind'];summary[kind]=summary.get(kind,0)+1
    result={'directory':str(work),'clients':results,'guard_event_counts':summary,'external_api_calls':external,
            'http2_observed':any(row['event']['metadata']['evidence'].get('http_version')=='HTTP/2.0' for row in records)}
    required={'http_request':3,'http_response':3,'websocket_message':2,'grpc_message':2,'dns_request':1,'dns_response':1,'tcp_message':2}
    result['verified_at']=time.time()
    result['guard_errors']=sum(r['verdict']['category']=='unknown' for r in records)
    result['all_verified']=all(v['client_ok'] for v in results.values()) and all(summary.get(k,0)>=n for k,n in required.items()) and result['guard_errors']==0
    (ROOT/'.runtime/network/validation-proxy.json').write_text(json.dumps(result,indent=2))
    (work/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
    if not result['all_verified']:raise SystemExit(1)

if __name__=='__main__':main()
