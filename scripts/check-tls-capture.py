#!/usr/bin/env python3
"""Bounded local TLS capability check. No external host, keylog or broad capture."""
import argparse
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def check(binary, client_kind, work):
    if not shutil.which('openssl'):
        return {'client':client_kind,'status':'unavailable','reason':'openssl_missing'}
    if client_kind=='curl' and not Path('/usr/bin/curl').exists():
        return {'client':client_kind,'status':'unavailable','reason':'curl_missing'}
    with tempfile.TemporaryDirectory(dir=work,prefix='tls-check-') as tmp:
        directory=Path(tmp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                        '-keyout',str(directory/'key.pem'),'-out',str(directory/'cert.pem'),
                        '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data=b'MOP_LOCAL_TLS_RESPONSE'
                self.send_response(200);self.send_header('Content-Length',str(len(data)))
                self.end_headers();self.wfile.write(data)
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory/'cert.pem',directory/'key.pem')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url=f'https://localhost:{server.server_port}/MOP_LOCAL_TLS_REQUEST'
        if client_kind=='python':
            code='import ssl,urllib.request,sys; print("READY",flush=True); input(); c=ssl.create_default_context(cafile=sys.argv[1]); o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); print(o.open(sys.argv[2],timeout=4).read().decode())'
            command=[sys.executable,'-c',code,str(directory/'cert.pem'),url]
        else:
            command=['/bin/sh','-c','echo READY; read ignored; exec /usr/bin/curl --noproxy "*" --fail --silent --show-error --max-time 4 --cacert "$1" "$2"',
                     'sh',str(directory/'cert.pem'),url]
        client=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        probe=None
        try:
            if client.stdout.readline().strip()!='READY':raise RuntimeError('Client did not become ready')
            maps=Path('/proc/self/maps').read_text()
            libraries=sorted({line.split()[-1] for line in maps.splitlines() if '/libssl.so' in line})
            if not libraries:return {'client':client_kind,'status':'unavailable','reason':'libssl_not_found'}
            library=libraries[0]
            probe=subprocess.Popen(['sudo','-n','timeout','--signal=INT','--kill-after=3','10',str(binary),
                'tls','--pid',str(client.pid),'--uid',str(os.getuid()),'--mapsize','16',
                '--libssl',library,'--listen=','--eventaddr','stdout'],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            captured=bytearray();deadline=time.monotonic()+6;ready=False
            while time.monotonic()<deadline and probe.poll() is None:
                if select.select([probe.stdout],[],[],.2)[0]:
                    chunk=os.read(probe.stdout.fileno(),65536)
                    if not chunk:break
                    captured.extend(chunk)
                    if len(captured)>1024*1024:raise RuntimeError('Probe diagnostic bound exceeded')
                    if b'probe started successfully.' in captured.lower():ready=True;break
            output,error=client.communicate('\n',timeout=6)
            tail=probe.communicate(timeout=15)[0];captured.extend(tail)
            request_seen=b'MOP_LOCAL_TLS_REQUEST' in captured and ('PID:'+str(client.pid)).encode() in captured
            response_seen=b'MOP_LOCAL_TLS_RESPONSE' in captured and ('PID:'+str(client.pid)).encode() in captured
            return {'client':client_kind,'status':'verified' if ready and client.returncode==0 and request_seen and response_seen else 'not_verified',
                    'probe_ready':ready,'request_observed':request_seen,'response_observed':response_seen,
                    'client_exit':client.returncode,'probe_exit':probe.returncode,'libssl':library,
                    'scope':'single_owned_process_local_tls_only'}
        finally:
            if client.poll() is None:client.kill();client.wait()
            if probe is not None and probe.poll() is None:
                # The root timeout remains a hard bound even if termination of
                # the sudo supervisor is denied or delayed.
                try:probe.terminate();probe.wait(timeout=15)
                except (OSError,subprocess.TimeoutExpired):pass
            server.shutdown();server.server_close();thread.join(timeout=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args()
    if os.getuid()==0:parser.error('Run as the target user; sudo is used only for the probe')
    results=[]
    for kind in ('python','curl'):
        try:results.append(check(args.binary,kind,args.work))
        except Exception as error:results.append({'client':kind,'status':'not_verified','reason':type(error).__name__})
    print(json.dumps({'checks':results,'external_requests':0,'persistent_probes_started':False},indent=2))


if __name__=='__main__':main()
