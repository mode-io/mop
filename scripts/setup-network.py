#!/usr/bin/env python3
"""Install the optional loopback, authenticated MOP protocol proxy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
VERSION='12.2.3'
SHA='2e95286b618fa6fd33e5e62a78c2e5112571d85f42ec2bac29b97ee242bdb5c5'
NAME='mitmproxy-'+VERSION+'-linux-x86_64.tar.gz'


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--offline',action='store_true');args=parser.parse_args()
    if os.getuid()==0:parser.error('Run as the target user')
    work=ROOT/'.runtime/network';work.mkdir(mode=0o700,parents=True,exist_ok=True);work.chmod(0o700)
    archive=ROOT/'.runtime'/NAME
    if not archive.exists():
        if args.offline:parser.error('Pinned proxy archive is not cached')
        with urllib.request.urlopen('https://downloads.mitmproxy.org/'+VERSION+'/'+NAME,timeout=30) as response,archive.open('wb') as output:
            size=0
            while data:=response.read(1024*1024):
                size+=len(data)
                if size>128*1024*1024:raise ValueError('Archive too large')
                output.write(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA:raise ValueError('Proxy archive checksum mismatch')
    directory=ROOT/'.runtime'/('mitmproxy-'+VERSION);directory.mkdir(exist_ok=True)
    binary=directory/'mitmdump'
    with tarfile.open(archive) as source:
        member=source.getmember('mitmdump')
        if not member.isfile() or member.size>64*1024*1024:raise ValueError('Invalid proxy archive member')
        expected=source.extractfile(member).read()
    if not binary.exists() or hashlib.sha256(binary.read_bytes()).digest()!=hashlib.sha256(expected).digest():
        temporary=directory/'mitmdump.tmp';temporary.write_bytes(expected);temporary.chmod(0o755);temporary.replace(binary)
    config=work/'config.json'
    settings=json.loads(config.read_text()) if config.exists() else {'username':'mop','password':secrets.token_hex(24),'port':18938}
    config.write_text(json.dumps(settings));config.chmod(0o600)
    ca=work/'ca';ca.mkdir(mode=0o700,exist_ok=True);ca.chmod(0o700)
    bundle=work/'ca-bundle.pem'
    bundle.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()+(b'\n'+(ca/'mitmproxy-ca-cert.pem').read_bytes() if (ca/'mitmproxy-ca-cert.pem').exists() else b''))
    bundle.chmod(0o600)
    options={'listen_host':'127.0.0.1','listen_port':settings['port'],'proxyauth':settings['username']+':'+settings['password'],
             'http2':True,'connection_strategy':'lazy','stream_large_bodies':'256k','ssl_insecure':False,'ssl_verify_upstream_trusted_ca':str(bundle),
             'mode':['regular@127.0.0.1:18938','dns@127.0.0.1:18953']}
    (ca/'config.yaml').write_text(json.dumps(options));(ca/'config.yaml').chmod(0o600)
    code_files={name:(ROOT/'scripts'/name).read_bytes() for name in ('mitm-adapter.py','capture_export.py')}
    revision=hashlib.sha256(b''.join(code_files.values())+json.dumps(options,sort_keys=True).encode()).hexdigest()[:16]
    code=work/('code-'+revision);code.mkdir(mode=0o700,exist_ok=True)
    for name,data in code_files.items():(code/name).write_bytes(data)
    script=work/('start-'+revision+'.sh')
    script.write_text('#!/bin/sh\nset -eu\numask 077\nexport MOP_NETWORK_DIR='+shlex.quote(str(work))+'\nexport MOP_ROOT='+shlex.quote(str(ROOT))+'\nexec '+shlex.quote(str(binary))+' -q --set '+shlex.quote('confdir='+str(ca))+' -s '+shlex.quote(str(code/'mitm-adapter.py'))+'\n')
    script.chmod(0o700)
    # The installed unit drops to the invoking user before loading project code.
    unit=f'''[Unit]
Description=MOP authenticated protocol proxy for UID {os.getuid()}
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=2
[Service]
User={os.getuid()}
Group={os.getgid()}
WorkingDirectory={ROOT}
ExecStart={script}
Restart=on-failure
RestartSec=10
UMask=0077
MemoryMax=512M
CPUQuota=100%
TasksMax=128
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths={work}
[Install]
WantedBy=multi-user.target
'''
    path=work/'mop-network.service';path.write_text(unit)
    name='mop-network-'+str(os.getuid())+'.service'
    destination='/etc/systemd/system/'+name
    previous=subprocess.run(['sudo','-n','cat',destination],capture_output=True,text=True)
    if previous.returncode==0 and not previous.stdout.startswith('[Unit]\nDescription=MOP authenticated protocol proxy'):
        raise ValueError('Refusing to replace an unmanaged proxy service')
    active=subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0
    changed=previous.stdout!=unit
    if changed or not active:
        subprocess.run(['sudo','-n','install','-m','644',str(path),destination],check=True)
        subprocess.run(['sudo','-n','systemctl','daemon-reload'],check=True)
        subprocess.run(['sudo','-n','systemctl','enable',name],check=True,capture_output=True)
        subprocess.run(['sudo','-n','systemctl','reset-failed',name],check=False,capture_output=True)
        subprocess.run(['sudo','-n','systemctl','restart',name],check=True)
    cert=ca/'mitmproxy-ca-cert.pem'
    for _ in range(40):
        if cert.exists() and (work/'status.json').exists() and time.time()-json.loads((work/'status.json').read_text()).get('updated_at',0)<3 and subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0:break
        time.sleep(.25)
    else:
        if changed:
            if previous.returncode==0:
                backup=work/'previous.service';backup.write_text(previous.stdout)
                subprocess.run(['sudo','-n','install','-m','644',str(backup),destination],check=True)
                subprocess.run(['sudo','-n','systemctl','daemon-reload'],check=True)
                if active:subprocess.run(['sudo','-n','systemctl','restart',name],check=False)
            else:subprocess.run(['sudo','-n','systemctl','disable','--now',name],check=False)
        raise RuntimeError('Proxy failed to start; previous service restored when available')
    bundle=work/'ca-bundle.pem'
    bundle.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()+b'\n'+cert.read_bytes())
    proxy='http://'+settings['username']+':'+settings['password']+'@127.0.0.1:'+str(settings['port'])
    exports={k:proxy for k in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy')}
    exports.update(SSL_CERT_FILE=str(bundle),REQUESTS_CA_BUNDLE=str(bundle),CURL_CA_BUNDLE=str(bundle),NODE_EXTRA_CA_CERTS=str(cert))
    lines=['# MOP proxy routing for this shell only. No system trust store is changed.']
    lines.extend('export '+key+'='+shlex.quote(value) for key,value in exports.items())
    lines.append('export NO_PROXY="localhost,127.0.0.1,::1${NO_PROXY:+,$NO_PROXY}"')
    lines.append('export no_proxy="$NO_PROXY"')
    (work/'env.sh').write_text('\n'.join(lines)+'\n');(work/'env.sh').chmod(0o600)
    tcp=work/'tcp';tcp.mkdir(mode=0o700,exist_ok=True);tcp.chmod(0o700)
    tcp_script=work/('start-tcp-'+revision+'.sh')
    tcp_script.write_text('#!/bin/sh\nset -eu\numask 077\nexport MOP_NETWORK_DIR='+shlex.quote(str(tcp))+'\nexport MOP_PROXY_MODE=tcp\nexport MOP_ROOT='+shlex.quote(str(ROOT))+'\nexec '+shlex.quote(str(binary))+' -q --set '+shlex.quote('confdir='+str(ca))+' -s '+shlex.quote(str(code/'mitm-adapter.py'))+' --mode socks5@127.0.0.1:18939 --set '+shlex.quote('tcp_hosts=.*')+'\n')
    tcp_script.chmod(0o700)
    tcp_unit=unit.replace('MOP authenticated protocol proxy','MOP authenticated TCP proxy').replace(str(script),str(tcp_script))
    tcp_name='mop-network-tcp-'+str(os.getuid())+'.service';tcp_destination='/etc/systemd/system/'+tcp_name
    old=subprocess.run(['sudo','-n','cat',tcp_destination],capture_output=True,text=True)
    if old.returncode==0 and not old.stdout.startswith('[Unit]\nDescription=MOP authenticated TCP proxy'):
        raise ValueError('Refusing to replace an unmanaged TCP service')
    if old.stdout!=tcp_unit or subprocess.run(['systemctl','is-active','--quiet',tcp_name]).returncode:
        tcp_file=work/'tcp.service';tcp_file.write_text(tcp_unit)
        subprocess.run(['sudo','-n','install','-m','644',str(tcp_file),tcp_destination],check=True)
        subprocess.run(['sudo','-n','systemctl','daemon-reload'],check=True)
        subprocess.run(['sudo','-n','systemctl','enable',tcp_name],check=True,capture_output=True)
        subprocess.run(['sudo','-n','systemctl','reset-failed',tcp_name],check=False,capture_output=True)
        subprocess.run(['sudo','-n','systemctl','restart',tcp_name],check=True)
    for _ in range(40):
        if (tcp/'status.json').exists() and time.time()-json.loads((tcp/'status.json').read_text()).get('updated_at',0)<3:break
        time.sleep(.25)
    else:raise RuntimeError('TCP proxy failed to start')
    print(json.dumps({'service':name,'listen':'127.0.0.1:'+str(settings['port']),'authentication':True,'changed':changed,
                     'system_trust_changed':False,'route_command':'mop-network exec -- COMMAND','env_file':str(work/'env.sh')}))

if __name__=='__main__':main()
