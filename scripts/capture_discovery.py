"""Discover bounded, owner-scoped TLS probe candidates without running binaries."""
import os
from pathlib import Path
import re
import pwd
import subprocess
import select
import time

CACHE={}
ON_CHILD=lambda pid:None

FAMILIES={
 'gotls':('crypto/tls.(*Conn).Read','crypto/tls.(*Conn).Write'),
 'openssl':('SSL_read','SSL_write','SSL_free'),
 'gnutls':('gnutls_record_recv','gnutls_record_send','gnutls_deinit'),
 'nspr':('PR_Read','PR_Write','PR_Close'),
}

def symbols(path,uid=None):
    result=set()
    for flags in (['-D','--defined-only'],['--defined-only']):
        options={'user':uid,'group':pwd.getpwuid(uid).pw_gid,'extra_groups':[]} if os.geteuid()==0 and uid else {}
        try:
            proc=subprocess.Popen(['/usr/bin/nm',*flags,str(path)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},**options)
            ON_CHILD(proc.pid)
            data=bytearray();deadline=time.monotonic()+4;bounded=True
            while True:
                if time.monotonic()>deadline or len(data)>8*1024*1024:bounded=False;break
                if not select.select([proc.stdout],[],[],.1)[0]:continue
                block=os.read(proc.stdout.fileno(),65536)
                if not block:break
                data.extend(block)
            if not bounded:proc.kill()
            proc.wait(timeout=2);proc.stdout.close()
            if not bounded:return set()
            for line in data.decode('utf-8','replace').splitlines():
                fields=line.split()
                if len(fields)>=3 and fields[-2] in ('T','t','W','w'):
                    name=fields[-1].split('@',1)[0]
                    if name.startswith(('SSL_','gnutls_record_','gnutls_deinit','PR_','crypto/tls.')):result.add(name)
            if any(set(names)<=result for names in FAMILIES.values()):break
        except (OSError,subprocess.TimeoutExpired):continue
    return result


def candidates(uid):
    paths=set()
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            if process.stat().st_uid!=uid:continue
            paths.add((process/'exe').resolve(strict=True))
            with (process/'maps').open() as stream:
                for index,line in enumerate(stream):
                    if index>8192:break
                    if any(name in line for name in ('libssl','libgnutls','libnspr','libboringssl')):
                        value=line.split()[-1]
                        if value.startswith('/'):paths.add(Path(value).resolve())
        except (OSError,ValueError):continue
    prefixes={p.parent.parent for p in paths if p.parent.name=='bin'}
    home=Path(pwd.getpwuid(uid).pw_dir).resolve()
    for name in ('anaconda3','miniconda3','miniforge3','mambaforge'):
        prefixes.add(home/name)
        if (home/name/'envs').is_dir():prefixes.update(list((home/name/'envs').iterdir())[:24])
    for prefix in prefixes:
        for pattern in ('libssl.so*','libgnutls.so*','libnspr4.so'):
            for value in (prefix/'lib').glob(pattern):
                if value.is_file():paths.add(value.resolve())
    for name in ('libssl.so.3','libgnutls.so.30','libnspr4.so'):
        path=Path('/usr/lib/x86_64-linux-gnu')/name
        if path.exists():paths.add(path.resolve())
    return sorted(paths,key=lambda p:(not any(x in p.name for x in ('ssl','gnutls','nspr','python')),str(p)))[:64]


def inspect(path,uid):
    path=Path(path).resolve()
    if not re.fullmatch(r'/[A-Za-z0-9_./+-]+',str(path)):return None
    try:
        info=path.stat()
        if not path.is_file() or info.st_uid not in (0,uid) or not 0<info.st_size<=256*1024*1024:return None
        with path.open('rb') as stream:
            if stream.read(4)!=b'\x7fELF':return None
    except OSError:return None
    key=(str(path),info.st_dev,info.st_ino,info.st_mtime_ns,info.st_size)
    if key in CACHE:return CACHE[key]
    if len(CACHE)>256:CACHE.clear()
    names=symbols(path,uid)
    for family,required in FAMILIES.items():
        if set(required)<=names:
            result={'path':str(path),'family':family,'extended':{'SSL_read_ex','SSL_write_ex'}<=names,
                    'identity':[info.st_dev,info.st_ino,info.st_mtime_ns,info.st_size]}
            CACHE[key]=result;return result
    CACHE[key]=None
    return None


def discover(uid):
    found=[];seen=set()
    for path in candidates(uid):
        item=inspect(path,uid)
        if item and tuple(item['identity'][:2]) not in seen:
            found.append(item);seen.add(tuple(item['identity'][:2]))
    rank={'gnutls':0,'nspr':1,'gotls':2,'openssl':3}
    return sorted(found,key=lambda x:(rank[x['family']], 'python' not in Path(x['path']).name, '/anaconda3/lib/' not in x['path'],x['path']))


if __name__=='__main__':
    import json
    print(json.dumps({'uid':os.getuid(),'targets':discover(os.getuid())},indent=2))
