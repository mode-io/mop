"""One per-user observer with a private Unix socket for all terminal views."""
import asyncio
from collections import Counter, OrderedDict, deque
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
from .paths import python_command
from .model_slots import state_root

LIMIT=8*1024*1024

def socket_path():return state_root()/'mopd.sock'

def request(value):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(4);client.connect(str(socket_path()))
        peer=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if peer[1]!=os.getuid():raise ValueError('Unexpected daemon owner')
        client.sendall(json.dumps(value).encode()+b'\n');data=bytearray()
        while True:
            block=client.recv(65536)
            if not block:break
            data.extend(block)
            if len(data)>LIMIT:raise ValueError('Daemon response too large')
        result=json.loads(data)
        if 'error' in result:raise ValueError(result['error'])
        return result

class Server:
    def __init__(self,engine):self.engine=engine;self.server=None;self.fd=None;self.clients=set();self.closing=False
    async def start(self):
        root=state_root();root.mkdir(parents=True,exist_ok=True,mode=0o700)
        if root.is_symlink() or root.stat().st_uid!=os.getuid():raise ValueError('Invalid state directory')
        root.chmod(0o700)
        self.fd=os.open(root/'daemon.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:os.close(self.fd);self.fd=None;raise ValueError('MOP daemon already running')
        path=socket_path()
        if path.exists():path.unlink()
        self.server=await asyncio.start_unix_server(self.handle,path=str(path),limit=16384)
        path.chmod(0o600)
    async def handle(self,reader,writer):
        if self.closing:
            writer.transport.abort();return
        self.clients.add(writer)
        try:
            peer=struct.unpack('3i',writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if peer[1]!=os.getuid():raise ValueError('Peer UID mismatch')
            raw=await asyncio.wait_for(reader.readline(),3)
            if len(raw)>16384:raise ValueError('Request too large')
            command=json.loads(raw);op=command.get('op')
            if op=='snapshot':
                result={'pid':os.getpid(),'summary':self.engine.summary(),'recent':list(self.engine.recent)[-128:],
                        'latest':list(self.engine.latest_advice.values())[-512:],
                        'models':self.engine.provider.model_status() if hasattr(self.engine.provider,'model_status') else {}}
                # Payload ceiling is explicit and does not silently drop a response.
                while len(json.dumps(result).encode())>LIMIT-1024 and (result['recent'] or result['latest']):
                    result['snapshot_limited']=True
                    key='latest' if len(result['latest'])>len(result['recent']) else 'recent'
                    result[key]=result[key][len(result[key])//2+1:]
            elif op=='models':
                result={'pid':os.getpid(),'summary':self.engine.summary(),
                        'models':self.engine.provider.model_status() if hasattr(self.engine.provider,'model_status') else {}}
            elif op=='level':self.engine.set_level(command['value']);result={'ok':True}
            elif op=='window':self.engine.set_window_ms(float(command['value']));result={'ok':True}
            elif op=='audit':
                from .core import Event
                event=Event.from_dict(command['event'])
                if event.source!='ui' or event.operation!='user_process_control':raise ValueError('Only UI action audit events are accepted')
                result={'accepted':self.engine.submit(event)}
            elif op=='stop':
                result={'stopping':True,'pid':os.getpid()};asyncio.get_running_loop().call_later(.1,os.kill,os.getpid(),signal.SIGTERM)
            else:raise ValueError('Unknown daemon command')
        except Exception as error:result={'error':type(error).__name__}
        try:
            writer.write(json.dumps(result).encode());await asyncio.wait_for(writer.drain(),3)
        except (asyncio.TimeoutError,ConnectionError):pass
        finally:
            writer.close()
            try:await asyncio.wait_for(writer.wait_closed(),1)
            except (asyncio.TimeoutError,ConnectionError):writer.transport.abort()
            finally:self.clients.discard(writer)
    async def close(self):
        self.closing=True
        if self.server:
            self.server.close()
            for writer in list(self.clients):writer.transport.abort()
            try:await asyncio.wait_for(self.server.wait_closed(),2)
            except asyncio.TimeoutError:pass
            socket_path().unlink(missing_ok=True)
        if self.fd is not None:os.close(self.fd);self.fd=None

class RemoteEngine:
    remote=True
    evidence_collector=None
    review_interval=0
    def __init__(self):
        self.stats=Counter();self.recent=deque(maxlen=128);self.latest_advice=OrderedDict();self.data={}
        self.provider=self;self.granularity=self;self.name='vllm-jev';self.next_refresh=0
    async def refresh(self,models_only=False):
        if time.monotonic()<self.next_refresh and getattr(self,'last_models_only',False)==models_only:return
        value=await asyncio.to_thread(request,{'op':'models' if models_only else 'snapshot'})
        self.next_refresh=time.monotonic()+.5;self.last_models_only=models_only
        if models_only:self.data.update(value)
        else:
            self.data=value
            self.recent=deque(value['recent'],maxlen=128)
            self.latest_advice=OrderedDict((r['event']['id'],r) for r in value['latest'])
        self.stats=Counter(value['summary'])
    def summary(self):return self.data['summary']
    def model_status(self):return self.data.get('models',{})
    def available_levels(self):return self.data['summary']['granularity']['available_levels']
    @property
    def level(self):return self.data['summary']['granularity']['level']
    @property
    def window_ms(self):return self.data['summary']['granularity']['window_ms']
    def set_level(self,value):request({'op':'level','value':value});self.next_refresh=0
    def set_window_ms(self,value):request({'op':'window','value':value});self.next_refresh=0
    def retain_visible_identities(self,rows):pass
    def submit(self,event):
        if event.source=='ui':return request({'op':'audit','event':event.payload()}).get('accepted',False)
        return False

class RemoteGranularity:
    def __init__(self,engine):self.engine=engine
    def summary(self):return self.engine.data['summary']['granularity']
    def available_levels(self):return self.summary()['available_levels']
    @property
    def level(self):return self.summary()['level']
    @property
    def window_ms(self):return self.summary()['window_ms']

async def watch(args,screen):
    engine=RemoteEngine();engine.granularity=RemoteGranularity(engine)
    await engine.refresh()
    if screen is not None:
        from .ui import monitor
        return await monitor(screen,engine,args.duration,args.interval,args.all_users,args.threads,ui=args.ui,user_filter=args.user,pid_filter=args.pids,iterations=args.iterations)
    count=0;start=time.monotonic()
    while args.duration is None or time.monotonic()-start<args.duration:
        await engine.refresh();print(json.dumps(engine.data),flush=True);count+=1
        if args.iterations and count>=args.iterations:break
        await asyncio.sleep(args.interval)
    return 0

def main(argv):
    import argparse
    parser=argparse.ArgumentParser(prog='mop daemon');parser.add_argument('action',choices=['start','stop','status'])
    args=parser.parse_args(argv)
    try:
        if args.action=='stop':
            result=request({'op':'stop'});pid=result['pid']
            for _ in range(300):
                try:
                    raw=Path('/proc')/str(pid)/'stat'
                    if raw.read_text().split(') ',1)[1].startswith('Z '):break
                except FileNotFoundError:break
                time.sleep(.1)
            else:raise ValueError('Daemon is still draining; check status before restarting')
            print('MOP daemon stopped.');return 0
        if args.action=='status':
            value=request({'op':'snapshot'});print(json.dumps({'pid':value['pid'],'summary':value['summary'],'models':value['models']},indent=2));return 0
        try:value=request({'op':'snapshot'});print('MOP daemon already running: '+str(value['pid']));return 0
        except (OSError,ValueError):pass
        root=state_root();root.mkdir(parents=True,exist_ok=True,mode=0o700)
        logfile=os.open(root/'daemon.log',os.O_CREAT|os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        try:
            child=subprocess.Popen(python_command('watch','--plain','--daemon-owner','--log',str(root/'decisions.jsonl')),stdin=subprocess.DEVNULL,stdout=logfile,stderr=subprocess.STDOUT,start_new_session=True)
        finally:os.close(logfile)
        for _ in range(60):
            if child.poll() is not None:raise ValueError('Daemon exited; inspect '+str(root/'daemon.log'))
            try:value=request({'op':'snapshot'});print('MOP daemon running: '+str(value['pid'])+'. Open mop, hmop or bmop.');return 0
            except (OSError,ValueError):time.sleep(.1)
        raise ValueError('Startup not confirmed; inspect '+str(root/'daemon.log'))
    except (OSError,ValueError) as error:print('MOP daemon: '+str(error));return 2
