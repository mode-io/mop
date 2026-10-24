"""Read bounded, root-owned collector exports without launching privileged tools."""
import asyncio
import json
import os
from pathlib import Path
import stat
import time
from .core import Event


async def follow(engine, path=None, source="system-content", owner=0, prefix="ambient"):
    path=Path(path or ('/var/log/mop-content/%d/events.jsonl' % os.getuid()))
    stream=None;identity=None;initial=True;last_sequence={};next_health=0
    try:
        while True:
            try:
                if time.monotonic()>=next_health:
                    next_health=time.monotonic()+2
                    try:
                        with (path.parent/'status.json').open('rb') as status_file:raw_status=status_file.read(16385)
                        if len(raw_status)>16384:raise ValueError('Oversized collector status')
                        status=json.loads(raw_status)
                        engine.stats[prefix+'_source_unavailable']=int(time.time()-status['updated_at']>5 or not all(status['children_running']))
                        counts=status.get('stats',{})
                        engine.stats[prefix+'_capture_gaps']=sum(v for k,v in counts.items() if isinstance(v,int) and any(word in k for word in ('dropped','truncated','overflow','omitted','unpaired','unsupported','errors','ambiguous','gaps')))
                    except (OSError,ValueError,KeyError):engine.stats[prefix+'_source_unavailable']=1
                info=path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:
                    raise ValueError('Ambient event stream must be a regular file owned by the configured collector user')
                current=(info.st_dev,info.st_ino)
                if stream is None or current!=identity or info.st_size<stream.tell():
                    if stream:stream.close()
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                    opened=os.fstat(fd)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_uid!=owner or opened.st_mode&0o022:
                        os.close(fd);raise ValueError('Ambient event stream changed ownership or type')
                    stream=os.fdopen(fd,'rb');identity=(opened.st_dev,opened.st_ino)
                    if initial:stream.seek(0,2);initial=False
                position=stream.tell();line=stream.readline(8193)
                if not line:
                    await asyncio.sleep(.2);continue
                if len(line)>8192:
                    engine.stats[prefix+'_oversized']+=1
                    while line and not line.endswith(b'\n'):line=stream.readline(8193)
                    continue
                if not line.endswith(b'\n'):
                    stream.seek(position);await asyncio.sleep(.1);continue
                raw=json.loads(line)
                if raw.get('source')!=source or raw.get('operation')!='captured_io':
                    raise ValueError('Unexpected ambient event schema')
                metadata=raw.get('metadata',{})
                if metadata.get('uid')!=os.getuid():continue
                collector=metadata.get('collector_id');seq=metadata.get('sequence')
                if not isinstance(collector,str) or type(seq) is not int:raise ValueError('Missing collector sequence')
                if collector in last_sequence and seq>last_sequence[collector]+1:
                    engine.stats[prefix+'_export_lost']+=seq-last_sequence[collector]-1
                if len(last_sequence)>8:last_sequence.clear()
                last_sequence[collector]=seq
                if metadata.get('kind')=='capture_gap':
                    engine.stats[prefix+'_observed_gaps']+=1
                    continue
                if metadata.get('kind')=='stdio' and not (metadata.get('evidence',{}).get('text') or metadata.get('evidence',{}).get('content_fragment')):
                    engine.stats[prefix+'_without_content']+=1;continue
                # PID is observation metadata, not joined to a live process by
                # number alone. Short-lived processes can already have exited.
                event=Event.from_dict(raw)
                while engine.queue.full():await asyncio.sleep(.01)
                if engine.submit(event):engine.stats[prefix+'_events']+=1
            except FileNotFoundError:
                initial=False
                await asyncio.sleep(1)
            except (ValueError,TypeError,json.JSONDecodeError):
                engine.stats[prefix+'_invalid']+=1
                await asyncio.sleep(.1)
    finally:
        if stream:stream.close()
