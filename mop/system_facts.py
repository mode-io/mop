"""Bounded Linux facts with provenance; no invented task intent or permissions."""
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

TCP_STATES={'01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV','04':'FIN_WAIT1','05':'FIN_WAIT2',
            '06':'TIME_WAIT','07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK','0A':'LISTEN','0B':'CLOSING'}
SECRET_FLAG=re.compile(r'(?i)(?:.*[-_])?(?:password|passwd|secret|token|api[-_]?key|authorization|credentials?|private[-_]?key|secret[-_]?key)')


def bounded(path,limit=65536):
    with open(path,'rb') as stream: raw=stream.read(limit+1)
    return raw[:limit],len(raw)>limit


def argument_facts(path,redact):
    raw,truncated=bounded(path,16384)
    args=raw.split(b'\0')
    if args and args[-1]==b'':args.pop()
    if truncated and args:args.pop()  # Do not expose a cut-off credential argument.
    original_count=len(args);args=[x.decode('utf-8',errors='replace') for x in args[:128]]
    clean=[];hide_next=False;long_arguments=0
    for value in args:
        if hide_next:clean.append('[REDACTED]');hide_next=False;continue
        flag=value.split('=',1)[0]
        if value.startswith('-') and SECRET_FLAG.fullmatch(flag.lstrip("-")):
            if '=' in value:clean.append(flag+'=[REDACTED]')
            else:clean.append(value);hide_next=True
        elif len(value)>2048:
            clean.append('[OMITTED: overlong argument]');long_arguments+=1
        else:clean.append(redact(value))
    return {'values':clean,'source':str(path),'bytes_observed':len(raw),
            'truncated':truncated or original_count>128 or bool(long_arguments),
            'note':'Argument order is preserved, including duplicate flags; effective settings require runtime confirmation.'}


def runtime_environment(path,redact):
    allowed={'LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','VIRTUAL_ENV','CONDA_PREFIX',
             'CUDA_VISIBLE_DEVICES','OMP_NUM_THREADS','MKL_NUM_THREADS','LANG','LC_ALL'}
    raw,cut=bounded(path,65536);entries=raw.split(b'\0')
    if cut:entries=entries[:-1]
    values={};shortened=[]
    for entry in entries:
        key,separator,value=entry.partition(b'=')
        name=key.decode('ascii',errors='ignore')
        if separator and name in allowed:
            text=redact(value.decode('utf-8',errors='replace'))
            if len(text)>512:shortened.append(name)
            values[name]=text[:512]
    return {'values':values,'source':str(path),'truncated':cut,'shortened_values':shortened,
            'scope':'Allowlisted runtime configuration only; credential variables and other values are excluded. Environment flags do not prove effective application settings.'}


def file_attributes(path):
    value=os.stat(path)
    return {'uid':value.st_uid,'gid':value.st_gid,'mode':stat.filemode(value.st_mode),
            'mode_octal':oct(stat.S_IMODE(value.st_mode)),'size_bytes':value.st_size,
            'inode':value.st_ino,'device':value.st_dev,'links':value.st_nlink,
            'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns,'world_writable':bool(value.st_mode&stat.S_IWOTH),
            'setuid':bool(value.st_mode&stat.S_ISUID),'setgid':bool(value.st_mode&stat.S_ISGID)}


def address(value,ipv6=False):
    host,port=value.split(':');raw=bytes.fromhex(host)
    if sys.byteorder=='little':raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
    ip=socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET,raw)
    return {'address':ip,'port':int(port,16),'loopback':ipaddress.ip_address(ip).is_loopback}


def sockets_for(path,inodes):
    results=[];coverage={}
    if not inodes:return results,{'status':'no sockets among captured descriptors'}
    for table in ['tcp','tcp6','udp','udp6','unix']:
        filename=path/'net'/table
        try:
            raw,cut=bounded(filename,262144)
            lines=raw.decode(errors='replace').splitlines()
            if cut:lines=lines[:-1]
            coverage[table]={'source':str(filename),'truncated':cut}
            for line in lines[1:]:
                fields=line.split()
                if table=='unix':
                    if len(fields)<7 or fields[6] not in inodes:continue
                    results.append({'protocol':'unix','inode':fields[6],'state_code':fields[5],
                                    'path':' '.join(fields[7:])[:256]})
                else:
                    if len(fields)<10 or fields[9] not in inodes:continue
                    results.append({'protocol':table,'inode':fields[9],
                                    'local':address(fields[1],table.endswith('6')),
                                    'remote':address(fields[2],table.endswith('6')),
                                    'state':TCP_STATES.get(fields[3],fields[3]) if table.startswith('tcp') else fields[3],
                                    'uid':int(fields[7])})
        except (OSError,ValueError,IndexError):coverage[table]={'status':'unavailable_or_unparsed'}
    coverage["unmatched_socket_inodes"]=sorted(inodes-{row["inode"] for row in results})
    return results,coverage


class SystemFacts:
    def __init__(self,root,redact):
        self.root,self.redact=Path(root),redact
        self.lock=threading.Lock();self.hashes={};self.gpu_at=0;self.gpu_rows=[];self.gpu_status='not sampled'

    def identity(self,pid):
        raw,_=bounded(self.root/str(pid)/'stat',4096);text=raw.decode(errors='replace')
        fields=text[text.rindex(')')+2:].split()
        return {'pid':int(pid),'name':self.redact(text[text.index('(')+1:text.rindex(')')]),
                'ppid':int(fields[1]),'start_ticks':int(fields[19]),'state':fields[0],
                'cpu_ticks':int(fields[11])+int(fields[12])}

    def executable(self,path):
        attrs=file_attributes(path)
        key=(attrs['device'],attrs['inode'],attrs['size_bytes'],attrs['mtime_ns'],attrs['ctime_ns'])
        if attrs['size_bytes']>16*1024*1024:
            attrs['sha256_status']='omitted: executable larger than 16 MiB'
            return attrs
        with self.lock:
            digest=self.hashes.get(key)
            if digest is None:
                raw,cut=bounded(path,16*1024*1024)
                if cut:attrs['sha256_status']='omitted: executable grew during read';return attrs
                after=file_attributes(path)
                if key!=(after['device'],after['inode'],after['size_bytes'],after['mtime_ns'],after['ctime_ns']):
                    attrs['sha256_status']='file changed while hashing';return attrs
                digest=hashlib.sha256(raw).hexdigest()
                if len(self.hashes)>=256:self.hashes.clear()
                self.hashes[key]=digest
        attrs['sha256']=digest;return attrs

    def gpu(self,identities):
        if str(self.root)!='/proc' or not shutil.which('nvidia-smi'):
            return {'status':'unavailable','source':'nvidia-smi'}
        with self.lock:
            if time.monotonic()-self.gpu_at>30:
                self.gpu_rows=[]
                try:
                    raw=subprocess.check_output(['nvidia-smi','--query-compute-apps=pid,used_memory,gpu_uuid',
                        '--format=csv,noheader,nounits'],text=True,stderr=subprocess.DEVNULL,timeout=2)
                    for row in list(csv.reader(raw.splitlines()))[:256]:
                        if len(row)!=3:continue
                        pid=int(row[0]);identity=self.identity(pid)
                        self.gpu_rows.append({'pid':pid,'start_ticks':identity['start_ticks'],
                                              'memory_mib':row[1].strip(),'gpu_uuid':row[2].strip()})
                    self.gpu_status='ok'
                except (OSError,ValueError,subprocess.SubprocessError):self.gpu_status='unavailable'
                self.gpu_at=time.monotonic()
            return {'status':self.gpu_status,'source':'nvidia-smi compute process query',
                    'sample_age_seconds':round(time.monotonic()-self.gpu_at,3),
                    'processes':[r for r in self.gpu_rows if (r['pid'],r['start_ticks']) in identities],
                    'scope':'This process and captured direct children; an open device file is not a GPU allocation.'}

    def collect(self,pid,include_args=True,tid=None):
        process_path=self.root/str(pid)
        path=process_path if tid is None or tid==pid else process_path/"task"/str(tid)
        data={'provenance':{},'coverage':{}}
        def collect(name,source,fn):
            try:
                value=fn();data[name]=value;data['provenance'][name]=str(source)
                data['coverage'][name]='available'
            except (OSError,ValueError,IndexError):data['coverage'][name]='unavailable'
        if include_args:collect('arguments',path/'cmdline',lambda:argument_facts(path/'cmdline',self.redact))
        else:data['coverage']['arguments']='disabled'
        collect('runtime_environment',path/'environ',lambda:runtime_environment(path/'environ',self.redact))
        collect('executable_attributes',path/'exe',lambda:self.executable(path/'exe'))
        collect('cwd_attributes',path/'cwd',lambda:file_attributes(path/'cwd'))
        collect('uid_map',path/'uid_map',lambda:bounded(path/'uid_map',4096)[0].decode(errors='replace').splitlines())
        collect('gid_map',path/'gid_map',lambda:bounded(path/'gid_map',4096)[0].decode(errors='replace').splitlines())
        collect('security_label',path/'attr/current',lambda:self.redact(bounded(path/'attr/current',1024)[0].decode(errors='replace')).strip())
        collect('cgroups',path/'cgroup',lambda:self.redact(bounded(path/'cgroup',4096)[0].decode(errors='replace')).splitlines())
        collect('limits',path/'limits',lambda:bounded(path/'limits',16384)[0].decode(errors='replace').splitlines())
        namespaces={}
        for name in ['mnt','pid','net','user','uts','ipc','cgroup']:
            try:namespaces[name]=os.readlink(path/'ns'/name)
            except OSError:namespaces[name]='unavailable'
        data['namespaces']=namespaces;data['provenance']['namespaces']=str(path/'ns')
        ancestry=[];seen={int(pid)}
        try:
            parent=self.identity(pid)['ppid']
            while parent>0 and parent not in seen and len(ancestry)<6:
                seen.add(parent);row=self.identity(parent)
                try:row['exe']=self.redact(os.readlink(self.root/str(parent)/'exe'))
                except OSError:pass
                ancestry.append(row);parent=row['ppid']
            data['ancestry']=ancestry;data['coverage']['ancestry']='bounded to 6 parents; non-atomic'
        except (OSError,ValueError,IndexError):data['coverage']['ancestry']='partially unavailable'
        threads=[];children=set();task_cut=False
        try:
            with os.scandir(process_path/'task') as entries:
                for i,entry in enumerate(entries):
                    if i>=128:task_cut=True;break
                    try:
                        raw,_=bounded(Path(entry.path)/'stat',4096);text=raw.decode(errors='replace');fields=text[text.rindex(')')+2:].split()
                        threads.append({'tid':int(entry.name),'name':self.redact(text[text.index('(')+1:text.rindex(')')]),
                                        'state':fields[0],'start_ticks':int(fields[19]),'cpu_ticks':int(fields[11])+int(fields[12])})
                        child_raw,_=bounded(Path(entry.path)/'children',4096)
                        children.update(int(value) for value in child_raw.split() if value.isdigit())
                    except (OSError,ValueError,IndexError):pass
            data['threads']={'details':threads,'truncated':task_cut,'limit':128}
            data['children']=[]
            for child in sorted(children)[:32]:
                try:data['children'].append(self.identity(child))
                except (OSError,ValueError,IndexError):pass
            data['coverage']['children']='from captured threads; up to 32 children'
        except OSError:data['coverage']['threads']='unavailable'
        descriptors=[];socket_inodes=set();fd_cut=False
        try:
            with os.scandir(path/'fd') as entries:
                for i,entry in enumerate(entries):
                    if i>=256:fd_cut=True;break
                    try:
                        target=os.readlink(entry.path)
                        row={'fd':int(entry.name),'target':self.redact(target)[:512],'deleted':target.endswith(' (deleted)')}
                        match=re.fullmatch(r'socket:\[(\d+)\]',target)
                        if match:socket_inodes.add(match.group(1))
                        try:
                            raw,_=bounded(path/'fdinfo'/entry.name,2048)
                            info=dict(line.split(':',1) for line in raw.decode(errors='replace').splitlines() if ':' in line)
                            flags=int(info.get('flags','0').strip(),8)
                            row['access_mode']={os.O_RDONLY:'read',os.O_WRONLY:'write',os.O_RDWR:'read_write'}.get(flags&os.O_ACCMODE,'unknown')
                            row['flags_octal']=oct(flags);row['offset']=info.get('pos','').strip()
                        except (OSError,ValueError):row['access_mode']='unavailable'
                        try:row['attributes']=file_attributes(entry.path)
                        except OSError:row['attributes_status']='unavailable'
                        descriptors.append(row)
                    except OSError:pass
            data['open_files']=descriptors;data['coverage']['open_files']={'limit':256,'truncated':fd_cut}
        except OSError:data['coverage']['open_files']='unavailable'
        network,coverage=sockets_for(path,socket_inodes)
        for record in network:
            if 'path' in record:record['path']=self.redact(record['path'])
        data['connections']=network;data['coverage']['connections']=coverage
        data['provenance']['connections']='Process FD socket inodes matched to its network-namespace tables; not a namespace-wide socket list'
        try:
            raw,cut=bounded(path/'maps',131072);lines=raw.decode(errors='replace').splitlines()
            if cut:lines=lines[:-1]
            mapped=[];writable_exec=0
            for line in lines:
                fields=line.split(maxsplit=5)
                if len(fields)<5:continue
                if 'w' in fields[1] and 'x' in fields[1]:writable_exec+=1
                if len(fields)>5 and 'x' in fields[1] and fields[5] not in mapped:mapped.append(self.redact(fields[5])[:256])
            data['mappings']={'executable_paths':mapped[:32],'writable_executable_regions':writable_exec,
                              'truncated':cut or len(mapped)>32,'note':'Mapping metadata only; no process memory contents.'}
        except OSError:data['coverage']['mappings']='unavailable'
        data['observed_identity']={'pid':int(pid),'tid':int(tid or pid),'proc_path':str(path)}
        own=self.identity(pid);identities={(int(pid),own['start_ticks'])}
        identities.update((r['pid'],r['start_ticks']) for r in data.get('children',[]))
        data['gpu']=self.gpu(identities)
        return data
