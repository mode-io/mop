#!/usr/bin/env python3
"""Install a pinned, root-owned, observation-only singleton service."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DIGEST='67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--uid',type=int,required=True);p.add_argument('--gid',type=int,required=True)
a=p.parse_args()
if os.geteuid()!=0 or a.uid<=0 or a.gid<0:p.error('requires root and a positive target UID')
archive=ROOT/'.runtime/tetragon/verified.tar.gz'
if hashlib.sha256(archive.read_bytes()).hexdigest()!=DIGEST:raise SystemExit('Checksum mismatch')
destination=Path('/opt/mop-tetragon');destination.mkdir(mode=0o755,exist_ok=True)
if destination.is_symlink() or destination.stat().st_uid!=0:raise SystemExit('Unsafe installation directory')
subprocess.run(['tar','--no-same-owner','-xzf',str(archive),'-C',str(destination)],check=True)
package=destination/'tetragon-v1.7.0-amd64'
subprocess.run(['chown','-R','root:root',str(destination)],check=True)
subprocess.run(['chmod','-R','go-w',str(destination)],check=True)
conf=destination/'conf';conf.mkdir(exist_ok=True)
policies=destination/'policies';policies.mkdir(exist_ok=True)
logs=Path('/var/log/mop-tetragon');logs.mkdir(mode=0o750,exist_ok=True)
if logs.is_symlink():raise SystemExit('Unsafe log directory')
os.chown(logs,0,a.gid);logs.chmod(0o750)
uid=str(a.uid)
expr=' || '.join(f'(has({kind}.process) && ({kind}.process.uid == uint({uid}) || {kind}.process.auid == uint({uid})))' for kind in ('process_exec','process_exit','process_kprobe'))
settings={'bpf-lib':str(package/'usr/local/lib/tetragon/bpf'),'btf':'/sys/kernel/btf/vmlinux',
 'bpf-dir':'mop-tetragon','server-address':'','health-server-address':'',
 'enable-process-cred':'true','enable-process-ns':'true','process-cache-size':'4096',
 'tracing-policy-dir':str(policies),'export-filename':str(logs/'events.jsonl'),
 'export-file-perm':'640','export-file-max-size-mb':'10','export-file-max-backups':'3',
 'export-allowlist':json.dumps({'cel_expression':[expr]})}
for key,value in settings.items():(conf/key).write_text(value+'\n')
paths=[str(ROOT),'/etc/','/root/.ssh/','/data1/hjingaa/.ssh/']
probes=[{'call':'security_file_permission','syscall':False,'return':True,
 'args':[{'index':0,'type':'file'},{'index':1,'type':'int'}],
 'returnArg':{'index':0,'type':'int'},'selectors':[{'matchArgs':[{'index':0,'operator':'Prefix','values':paths}]}]},
 {'call':'tcp_connect','syscall':False,'return':True,'args':[{'index':0,'type':'sock'}],'returnArg':{'index':0,'type':'int'}},
 {'call':'sys_openat','syscall':True,'return':True,'args':[{'index':1,'type':'string'}],
 'returnArg':{'index':0,'type':'int'},'selectors':[{'matchArgs':[{'index':1,'operator':'Prefix','values':['/etc/shadow','/root/.ssh/','/data1/hjingaa/.ssh/']}]}]}]
(policies/'observe.yaml').write_text(json.dumps({'apiVersion':'cilium.io/v1alpha1','kind':'TracingPolicy','metadata':{'name':'mop-default-observe'},'spec':{'kprobes':probes}},indent=2))
unit=f'''[Unit]
Description=MOP Tetragon observation collector
After=local-fs.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=simple
User=root
Group={a.gid}
UMask=0027
ExecStart={package}/usr/local/bin/tetragon --config-dir={conf}
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
Environment=GOMEMLIMIT=640MiB
MemoryMax=1G
CPUQuota=100%
[Install]
WantedBy=multi-user.target
'''
Path('/etc/systemd/system/mop-tetragon.service').write_text(unit)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','mop-tetragon.service'],check=True)
print('Installed mop-tetragon.service; observer only, no model inference in this service.')
