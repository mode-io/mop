"""Identify MOP observer processes to avoid reviewing the monitor's own I/O."""
import os
from pathlib import Path
import time

_cache={}

def is_monitor(pid):
    now=time.monotonic();cached=_cache.get(pid)
    if cached and now-cached[0]<1:return cached[1]
    found=False
    try:
        root=Path('/proc')/str(pid)
        if root.stat().st_uid==os.getuid():
            with (root/'cmdline').open('rb') as stream:argv=stream.read(8192).split(b'\0')
            found=any(arg==b'-m' and i+1<len(argv) and argv[i+1]==b'mop' for i,arg in enumerate(argv))
            found=found or (len(argv)>2 and argv[1]==b'-I' and argv[2]==os.fsencode(Path(__file__).with_name('_launch.py')))
    except OSError:pass
    if len(_cache)>4096:_cache.clear()
    _cache[pid]=(now,found)
    return found


def _telemetry_write(event, project_root=None):
    """Exclude allowed write-permission checks for the proxy's heartbeat file."""
    import re
    root=Path(project_root) if project_root else Path(__file__).resolve().parents[1]
    if event.source!='tetragon' or event.operation!='security_file_permission':return False
    metadata=event.metadata;process=metadata.get('process',{})
    binary=str(root/'.runtime/mitmproxy-12.2.3/mitmdump')
    if process.get('binary')!=binary or process.get('uid')!=os.getuid():return False
    observation=metadata.get('observation',{})
    if observation.get('function_name')!='security_file_permission' or metadata.get('outcome')!='nonnegative_return':return False
    args=observation.get('args',[])
    if len(args)!=2 or args[1].get('int_arg')!=2 or observation.get('return',{}).get('int_arg')!=0:return False
    path=args[0].get('file_arg',{}).get('path','')
    prefix=re.escape(str(root/'.runtime/network'))
    return bool(re.fullmatch(prefix+r'/(?:tcp/|reverse-[0-9]+/)?status\.tmp',path))


def is_telemetry_write(event, project_root=None):
    try:return _telemetry_write(event,project_root)
    except (TypeError,AttributeError,ValueError):return False
