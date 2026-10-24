#!/usr/bin/env python3
"""Exercise real TLS stacks against a private loopback HTTPS endpoint."""
import ctypes
import gzip
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]


def nss_client(db,port):
    nss=ctypes.CDLL('libnss3.so');nspr=ctypes.CDLL('libnspr4.so');tls=ctypes.CDLL('libssl3.so')
    nss.NSS_Init.argtypes=[ctypes.c_char_p];nss.NSS_Init.restype=ctypes.c_int
    assert nss.NSS_Init(('sql:'+db).encode())==0
    tls.NSS_SetDomesticPolicy.restype=ctypes.c_int;assert tls.NSS_SetDomesticPolicy()==0
    nspr.PR_ImportTCPSocket.argtypes=[ctypes.c_int];nspr.PR_ImportTCPSocket.restype=ctypes.c_void_p
    tls.SSL_ImportFD.argtypes=[ctypes.c_void_p,ctypes.c_void_p];tls.SSL_ImportFD.restype=ctypes.c_void_p
    tls.SSL_SetURL.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
    tls.SSL_ResetHandshake.argtypes=[ctypes.c_void_p,ctypes.c_int]
    tls.SSL_ForceHandshake.argtypes=[ctypes.c_void_p]
    nspr.PR_Write.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];nspr.PR_Write.restype=ctypes.c_int
    nspr.PR_Read.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];nspr.PR_Read.restype=ctypes.c_int
    nspr.PR_Close.argtypes=[ctypes.c_void_p]
    sock=socket.create_connection(('127.0.0.1',int(port)),timeout=5);sock.settimeout(None)
    fd=tls.SSL_ImportFD(None,nspr.PR_ImportTCPSocket(sock.detach()));assert fd
    assert tls.SSL_SetURL(fd,b'localhost')==0
    assert tls.SSL_ResetHandshake(fd,0)==0
    assert tls.SSL_ForceHandshake(fd)==0
    request=b'GET /nss HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
    assert nspr.PR_Write(fd,ctypes.create_string_buffer(request),len(request))==len(request)
    output=bytearray();buffer=ctypes.create_string_buffer(2048)
    while True:
        n=nspr.PR_Read(fd,buffer,len(buffer))
        if n<=0:break
        output.extend(buffer.raw[:n])
    nspr.PR_Close(fd)
    assert b'hello from TLS server' in output
    print('NSS HTTPS response received')


def main():
    work=ROOT/'artifacts'/('protocol-check-'+str(int(time.time())));work.mkdir(mode=0o700)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(work/'key.pem'),
        '-out',str(work/'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=json.dumps({'message':'hello from TLS server','path':self.path}).encode()
            compressed=self.path.endswith('gzip')
            if compressed:body=gzip.compress(body)
            self.send_response(200);self.send_header('Content-Type','application/json')
            if compressed:self.send_header('Content-Encoding','gzip')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(work/'cert.pem',work/'key.pem')
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    db=work/'nssdb';db.mkdir()
    subprocess.run(['certutil','-N','-d','sql:'+str(db),'--empty-password'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['certutil','-A','-d','sql:'+str(db),'-n','MOP local test CA','-t','CT,C,C','-i',str(work/'cert.pem')],check=True)
    source='''package main
import("bufio";"crypto/tls";"crypto/x509";"fmt";"io";"net/http";"os")
func main(){fmt.Println("READY");bufio.NewReader(os.Stdin).ReadString('\\n');pem,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};roots:=x509.NewCertPool();roots.AppendCertsFromPEM(pem);c:=http.Client{Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots},ForceAttemptHTTP2:false}};r,e:=c.Get(os.Args[2]);if e!=nil{panic(e)};defer r.Body.Close();b,e:=io.ReadAll(r.Body);if e!=nil{panic(e)};fmt.Println(string(b))}
'''
    (work/'client.go').write_text(source)
    env=os.environ.copy();env['GOCACHE']=str(ROOT/'.cache/go-build');env['GOTMPDIR']=str(ROOT/'.runtime')
    subprocess.run(['go','build','-o',str(work/'go-client'),str(work/'client.go')],check=True,env=env,timeout=90)
    go=subprocess.Popen([str(work/'go-client'),str(work/'cert.pem'),f'https://localhost:{server.server_port}/go'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert go.stdout.readline().strip()=='READY'
    results={};start=time.time()
    try:
        deadline=time.monotonic()+55
        while time.monotonic()<deadline:
            status=json.loads(Path('/var/log/mop-content/1001/status.json').read_text())
            if status.get('adapters',{}).get(str(work/'go-client'),{}).get('status')=='probe_started':
                time.sleep(3);break
            time.sleep(1)
        go_out,go_err=go.communicate('\n',timeout=15);results['go']={'pid':go.pid,'exit':go.returncode,'output':go_out[-250:],'error':go_err[-250:]}
        commands={
          'gnutls':['gnutls-cli','--logfile',str(work/'gnutls.log'),'--x509cafile',str(work/'cert.pem'),'-p',str(server.server_port),'localhost'],
          'nss':[sys.executable,__file__,'--nss',str(db),str(server.server_port)],
          'openssl_gzip':['curl','--silent','--show-error','--compressed','--cacert',str(work/'cert.pem'),f'https://localhost:{server.server_port}/gzip'],
        }
        for name,cmd in commands.items():
            child=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:out,err=child.communicate('GET /gnutls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' if name=='gnutls' else None,timeout=15)
            except subprocess.TimeoutExpired:child.kill();out,err=child.communicate()
            results[name]={'pid':child.pid,'exit':child.returncode,'output':out[-250:],'error':err[-250:]}
        time.sleep(3)
        rows=[]
        path=Path('/var/log/mop-content/1001/events.jsonl')
        for file in reversed([path]+[path.with_name(path.name+'.'+str(i)) for i in range(1,4)]):
            if file.exists():
                for line in file.read_text().splitlines():
                    try:
                        row=json.loads(line)
                        if row['metadata']['captured_at']>=start:rows.append(row)
                    except (ValueError,KeyError):pass
        for name,result in results.items():
            records=[r['metadata'] for r in rows if r['metadata']['observed_pid']==result['pid']]
            result['request_captured']=any(r['kind']=='http_request' for r in records)
            result['response_captured']=any(r['kind']=='http_response' and isinstance(r['evidence'].get('body'),dict) and r['evidence']['body'].get('message')=='hello from TLS server' for r in records)
        (work/'result.json').write_text(json.dumps(results,indent=2))
        report={'directory':str(work),'results':results,'external_api_calls':0,'verified_at':time.time(),
                'all_verified':all(v['exit']==0 and v['request_captured'] and v['response_captured'] for v in results.values())}
        (ROOT/'.runtime/network/validation-passive.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))
        if not report['all_verified']:raise SystemExit(1)
    finally:
        if go.poll() is None:go.kill();go.wait()
        server.shutdown();server.server_close()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--nss':nss_client(sys.argv[2],sys.argv[3])
    else:main()
