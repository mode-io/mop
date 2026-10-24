#!/usr/bin/env python3
"""Run an authenticated loopback reverse adapter, including HTTP/3 over QUIC v1."""
import argparse
import os
import json
from pathlib import Path
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',required=True);p.add_argument('--port',type=int,default=18940);a=p.parse_args()
    url=urllib.parse.urlsplit(a.upstream)
    if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        p.error('Use an HTTP(S) origin without credentials, path, query or fragment')
    if not 1024<=a.port<=65535:p.error('Use an unprivileged listening port')
    work=ROOT/'.runtime/network'/('reverse-'+str(a.port));work.mkdir(mode=0o700,exist_ok=True);work.chmod(0o700)
    env=os.environ.copy();env.update(MOP_ROOT=str(ROOT),MOP_NETWORK_DIR=str(work),MOP_PROXY_MODE='reverse',MOP_REVERSE_HTTP3='1' if url.scheme=='https' else '0')
    binary=ROOT/'.runtime/mitmproxy-12.2.3/mitmdump'
    original_ca=ROOT/'.runtime/network/ca';ca=ROOT/'.runtime/network/reverse-ca';ca.mkdir(mode=0o700,exist_ok=True);ca.chmod(0o700)
    for name in ('mitmproxy-ca.pem','mitmproxy-ca-cert.pem'):
        target=ca/name
        if not target.exists():target.symlink_to(original_ca/name)
    (ca/'config.yaml').write_text(json.dumps({'proxyauth':None,'ssl_insecure':False,'connection_strategy':'lazy','http2':True,'http3':True,
        'ssl_verify_upstream_trusted_ca':str(ROOT/'.runtime/network/ca-bundle.pem'),'stream_large_bodies':'256k'}))
    argv=[str(binary),'-q','--set','confdir='+str(ca),'--set','proxyauth=',
          '--mode','reverse:'+a.upstream.rstrip('/')+'@127.0.0.1:'+str(a.port),'-s',str(ROOT/'scripts/mitm-adapter.py')]
    os.execve(binary,argv,env)

if __name__=='__main__':main()
