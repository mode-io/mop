#!/usr/bin/env python3
"""Install a root-owned, UID-scoped collector with bounded resources and rollback."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile


def run(*args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=30)


def directory(path,mode=0o755,gid=0):
    path.mkdir(mode=mode,exist_ok=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('Unsafe managed directory: '+str(path))
    os.chown(path,0,gid);path.chmod(mode)


def atomic(path,data,mode=0o644):
    if path.is_symlink():raise ValueError('Refusing a symlink destination')
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.mop-')
    try:
        with os.fdopen(fd,'wb') as output:output.write(data)
        os.chmod(tmp,mode);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--uid',type=int,required=True);p.add_argument('--gid',type=int,required=True)
    p.add_argument('--agent',type=Path,required=True);p.add_argument('--tls',action='store_true')
    p.add_argument('--rollback',action='store_true')
    p.add_argument('--libssl',default='/usr/lib/x86_64-linux-gnu/libssl.so.3')
    a=p.parse_args()
    if os.geteuid()!=0 or a.uid<=0 or a.gid<0:p.error('Root and a non-root target UID are required')
    pwd.getpwuid(a.uid)
    config_dir=Path('/etc/mop-content');directory(config_dir)
    transaction=config_dir/(str(a.uid)+'.transaction.json')
    config=config_dir/(str(a.uid)+'.json')
    unit=Path('/etc/systemd/system')/('mop-content-'+str(a.uid)+'.service')
    if a.rollback:
        if not transaction.exists():print(json.dumps({'status':'no_transaction'}));return
        record=json.loads(transaction.read_text())
        if unit.is_symlink() or hashlib.sha256(unit.read_bytes()).hexdigest()!=record['new_unit_sha256']:
            raise ValueError('Unit changed after installation; refusing rollback')
        run('systemctl','stop',unit.name,check=False)
        if record['unit'] is None:run('systemctl','disable',unit.name,check=False)
        for path,key in ((unit,'unit'),(config,'config')):
            if record[key] is None:path.unlink(missing_ok=True)
            else:atomic(path,base64.b64decode(record[key]),0o644 if key=='unit' else 0o600)
        run('systemctl','daemon-reload')
        if record['active']:run('systemctl','start',unit.name)
        transaction.unlink();print(json.dumps({'status':'rolled_back'}));return
    base=Path('/opt/mop-tools');directory(base)
    raw=a.agent.read_bytes()
    if len(raw)>128*1024:raise ValueError('Collector source exceeds limit')
    helper=a.agent.with_name('capture_discovery.py').read_bytes()
    h2=a.agent.with_name('capture_http2.py').read_bytes()
    if len(helper)>65536:raise ValueError('Discovery source exceeds limit')
    digest=hashlib.sha256(raw+helper+h2).hexdigest();code=base/('content-'+digest[:20]);directory(code)
    agent=code/'agent.py'
    if agent.exists() and agent.read_bytes()!=raw:raise ValueError('Managed collector code was modified')
    atomic(agent,raw)
    atomic(code/'capture_discovery.py',helper)
    atomic(code/'capture_http2.py',h2)
    logs=Path('/var/log/mop-content');directory(logs)
    user_logs=logs/str(a.uid);directory(user_logs,0o750,a.gid)
    lib=Path(a.libssl).resolve()
    if a.tls and (not lib.is_file() or lib.stat().st_uid!=0 or lib.stat().st_mode&0o022):
        raise ValueError('TLS probing requires a root-owned system library')
    old_unit=unit.read_bytes() if unit.exists() else None
    old_config=config.read_bytes() if config.exists() else None
    if old_unit and not old_unit.startswith(b'# Managed by MOP content installer\n'):
        raise ValueError('Refusing to replace an unmanaged service')
    settings={'owner':'mop-content-installer','uid':a.uid,'log_dir':str(user_logs),
              'tls_enabled':a.tls,'tls_ex_enabled':a.tls and lib.name=='libssl.so.3',
              'libssl':str(lib),'ecapture':'/opt/mop-tools/ecapture-2.8.2/ecapture'}
    blob=(json.dumps(settings,sort_keys=True,indent=2)+'\n').encode()
    service=f'''# Managed by MOP content installer
[Unit]
Description=MOP content collector for UID {a.uid}
After=local-fs.target
StartLimitIntervalSec=60
StartLimitBurst=2
[Service]
Type=simple
User=root
Group={a.gid}
UMask=0027
RuntimeDirectory=mop-content-{a.uid}
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/python3 -I {agent} --config {config}
Restart=on-failure
RestartSec=10
KillMode=control-group
TimeoutStopSec=15
MemoryMax=512M
CPUQuota=100%
TasksMax=128
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths={user_logs} /run/mop-content-{a.uid} -/sys/kernel/debug/tracing -/sys/kernel/tracing
[Install]
WantedBy=multi-user.target
'''.encode()
    was_active=run('systemctl','is-active','--quiet',unit.name,check=False).returncode==0
    if old_unit==service and old_config==blob:
        print(json.dumps({'status':'reused','active':was_active,'unit':unit.name,'log_dir':str(user_logs)}));return
    try:
        atomic(transaction,json.dumps({'unit':base64.b64encode(old_unit).decode() if old_unit else None,
            'config':base64.b64encode(old_config).decode() if old_config else None,'active':was_active,
            'new_unit_sha256':hashlib.sha256(service).hexdigest()}).encode(),0o600)
        atomic(config,blob,0o600);atomic(unit,service)
        run('systemctl','daemon-reload')
        run('systemctl','enable',unit.name)
        run('systemctl','reset-failed',unit.name,check=False)
        run('systemctl','restart' if was_active else 'start',unit.name)
        print(json.dumps({'status':'installed','unit':unit.name,'log_dir':str(user_logs)}))
    except Exception:
        run('systemctl','stop',unit.name,check=False)
        if old_unit is None:
            run('systemctl','disable',unit.name,check=False);unit.unlink(missing_ok=True)
        else:atomic(unit,old_unit)
        if old_config is None:config.unlink(missing_ok=True)
        else:atomic(config,old_config,0o600)
        run('systemctl','daemon-reload')
        if was_active:run('systemctl','start',unit.name,check=False)
        transaction.unlink(missing_ok=True)
        raise


if __name__=='__main__':main()
