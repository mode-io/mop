"""Bounded Tetragon JSON adapter. No enforcement or implicit PID-only association."""
import asyncio
from collections import OrderedDict, deque
from datetime import datetime
import json
import hashlib
import math
import os
import re
from pathlib import Path
import stat
import time

from .content import redact_content
from .core import Event

KINDS = ('process_exec', 'process_exit', 'process_kprobe', 'process_tracepoint', 'process_uprobe', 'process_loader', 'process_lsm', 'process_usdt')
LIMIT = 65536


def bounded(value, depth=0):
    if depth > 5: return {'omitted': 'nesting limit'}
    if isinstance(value, str):
        if len(value) > 2048: return {'omitted': 'string exceeds budget', 'length': len(value)}
        return redact_content(value)
    if isinstance(value, dict):
        return {str(k): bounded(v, depth+1) for k,v in list(value.items())[:32]}
    if isinstance(value, list): return [bounded(v, depth+1) for v in value[:16]]
    if value is None or type(value) in (int, bool): return value
    if type(value) is float and math.isfinite(value): return value
    return {'omitted': 'unsupported value'}


def process_info(process):
    keys = ('exec_id','parent_exec_id','pid','tid','uid','auid','binary','arguments','cwd',
            'start_time','flags','cap','credentials','ns','docker','pod','process_credentials','namespaces','binary_properties')
    data = {key: process[key] for key in keys if key in process}
    # Redact secret-like mapping keys before structural projection.
    result = bounded(json.loads(redact_content(json.dumps(data, ensure_ascii=False))))
    for key in ('exec_id', 'parent_exec_id'):
        value = process.get(key)
        if isinstance(value, str) and 0 < len(value) <= 1024:
            result[key] = 'exec:' + hashlib.sha256(value.encode()).hexdigest()
    return result


class Adapter:
    def __init__(self, uid=None, include_args=True):
        self.uid, self.include_args = uid, include_args
        self.history = OrderedDict()

    def parse(self, raw):
        if not isinstance(raw, dict): raise ValueError('event must be an object')
        kinds = [key for key in KINDS if key in raw]
        if not kinds: return None
        if len(kinds) != 1: raise ValueError('ambiguous event kind')
        kind = kinds[0]; body = raw[kind]
        if not isinstance(body, dict): raise ValueError('invalid event body')
        process = body.get('process')
        if not isinstance(process, dict): raise ValueError('missing process')
        pid, uid, tid = process.get('pid'), process.get('uid'), process.get('tid', process.get('pid'))
        if any(type(v) is not int or v < 0 for v in (pid,uid,tid)) or pid == 0:
            raise ValueError('invalid process identity')
        if self.uid is not None and uid != self.uid and process.get("auid") != self.uid: return None
        timestamp = raw.get('time')
        if not isinstance(timestamp, str): raise ValueError('missing source timestamp')
        normalized = re.sub(r'(\.\d{6})\d+(?=Z|[+-]\d{2}:\d{2}$)', r'\1', timestamp)
        parsed = datetime.fromisoformat(normalized.replace('Z','+00:00'))
        if parsed.tzinfo is None: raise ValueError('timestamp requires timezone')
        observed_at = parsed.timestamp()
        if not math.isfinite(observed_at): raise ValueError('invalid timestamp')
        proc = process_info(process)
        parent = process_info(body['parent']) if isinstance(body.get('parent'),dict) else {}
        if not self.include_args:
            proc.pop('arguments',None); parent.pop('arguments',None)
        operation = {'process_exec':'process_exec','process_exit':'process_exit'}.get(kind)
        if operation is None:
            operation = body.get('function_name') or body.get('event') or kind
        if not isinstance(operation,str): raise ValueError('invalid operation')
        operation = operation[:128]
        detail_keys = ('function_name','subsys','event','args','return','action','return_action',
                       'policy_name','message','signal','status','tags','kernel_stack_trace','user_stack_trace',
                       'path','symbol','offset','buildid','ima_hash','data','provider','name')
        details = {key:body[key] for key in detail_keys if key in body}
        details = bounded(json.loads(redact_content(json.dumps(details, ensure_ascii=False))))
        result = details.get('return')
        # Only a captured return value supports success/failure at this hook.
        ret = None
        if isinstance(result,dict):
            for key in ('int_arg','long_arg','int64_arg'):
                value = result.get(key)
                if type(value) is int: ret=value;break
                if isinstance(value,str) and value.lstrip('-').isdigit(): ret=int(value);break
        outcome = 'not_reported' if ret is None else 'negative_return' if ret < 0 else 'nonnegative_return'
        ancestors = body.get('ancestors', [])
        if not isinstance(ancestors, list): ancestors = []
        ancestors = [process_info(a) for a in ancestors[:6] if isinstance(a,dict)]
        if not self.include_args:
            for ancestor in ancestors: ancestor.pop('arguments', None)
        metadata = {'ancestors':ancestors, 'ancestors_omitted':max(0,len(body.get('ancestors', []))-6) if isinstance(body.get('ancestors', []),list) else 0, 'tetragon_kind':kind, 'source_timestamp':timestamp,
                    'projection_limits':{'string_chars':2048,'list_items':16,'mapping_keys':32,'depth':5}, 'node':bounded(raw.get('node_name','')),
                    'process':proc, 'parent':parent, 'observation':details,
                    'outcome':outcome,
                    'identity_note':'Tetragon exec_id retained; no live /proc generation inferred from PID.',
                    'scope':'Selected Tetragon policies and adapter UID filter; not all syscalls or program contents.',
                    'limitations':['Hook entry does not prove operation success.',
                        'A hook return is not proof of complete application behavior or data exfiltration.',
                        'Upstream event loss cannot be determined from this JSON stream alone.',
                        'Payload is bounded and redacted best effort; it is untrusted evidence.']}
        exec_id = process.get('exec_id'); node = raw.get('node_name','')
        if isinstance(exec_id,str) and 0 < len(exec_id) <= 1024 and isinstance(node,str) and len(node)<=256:
            key=(node,exec_id)
            previous=self.history.get(key,deque(maxlen=6))
            metadata['recent_same_execution']=[item for item in previous if 0<=observed_at-item['timestamp']<=30]
            previous.append({'timestamp':observed_at,'operation':operation,'outcome':outcome,
                             'policy':details.get('policy_name','')})
            self.history[key]=previous;self.history.move_to_end(key)
            while len(self.history)>4096:self.history.popitem(last=False)
        # Fixed model-evidence budget. Never silently truncate structured JSON.
        if len(json.dumps(metadata).encode()) > 20000:
            metadata['ancestors']=[{k:v for k,v in a.items() if k in ('exec_id','pid','uid','binary')} for a in ancestors]
            metadata['observation']={'omitted':'observation exceeds model budget'}
            metadata['process']={k:v for k,v in proc.items() if k in ('exec_id','pid','uid','binary')}
            metadata['parent']={k:v for k,v in parent.items() if k in ('exec_id','pid','uid','binary')}
        binary=process.get('binary','')
        return Event(operation,'tetragon',pid,tid,Path(binary).name[:256] if isinstance(binary,str) else '',
                     metadata=metadata,timestamp=observed_at)



class Coalescer:
    """Group a short execution window; failed returns bypass grouping."""
    def __init__(self, engine, window_ms=250, emit=None):
        self.engine, self.seconds = engine, window_ms / 1000
        self.groups = OrderedDict()
        self.emit = emit or engine.submit
        self.next_tick = 0

    def flush(self, key):
        group = self.groups.pop(key)
        event, observations, opened, count = group
        if count > 1:
            event.operation = 'kernel_activity_window'
            event.metadata.pop('observation', None)
            event.metadata.pop('recent_same_execution', None)
            event.metadata['observations'] = list(observations.values())
            event.metadata['raw_event_count'] = count
            event.metadata['window_ms'] = round((time.monotonic()-opened)*1000, 2)
            event.metadata['decision_scope'] = 'group; not per-operation clearance'
            self.engine.stats['tetragon_coalesced_events'] += count - 1
        self.emit(event)

    def offer(self, event):
        self.tick()
        process = event.metadata.get('process', {})
        token = process.get('exec_id')
        key = (event.metadata.get('node'), token, event.tid,
               json.dumps({k:process.get(k,{}) for k in ('process_credentials','ns','cap')}, sort_keys=True))
        if not self.seconds or not token or event.metadata.get('outcome') == 'negative_return':
            if key in self.groups: self.flush(key)
            self.emit(event)
            return
        observation = {'operation': event.operation, 'outcome': event.metadata['outcome'],
                       'details': event.metadata['observation']}
        signature = json.dumps(observation, sort_keys=True)
        if key in self.groups and not 0 <= event.timestamp-self.groups[key][0].timestamp <= self.seconds:
            self.flush(key)
        if key not in self.groups:
            if len(self.groups) >= 256: self.flush(next(iter(self.groups)))
            self.groups[key] = [event, OrderedDict(), time.monotonic(), 0]
        group = self.groups[key]
        if signature not in group[1] and (len(group[1]) >= 8 or sum(map(len, group[1])) + len(signature) > 12000):
            self.flush(key)
            self.groups[key] = [event, OrderedDict(), time.monotonic(), 0]
            group = self.groups[key]
        item = group[1].setdefault(signature, {**observation, 'count': 0,
                    'first_timestamp': event.timestamp, 'last_timestamp': event.timestamp})
        item['count'] += 1; item['last_timestamp'] = event.timestamp
        group[3] += 1
        if group[3] >= 64 or event.operation == 'process_exit': self.flush(key)

    def tick(self, all_groups=False):
        now = time.monotonic()
        if not all_groups and now < self.next_tick: return
        self.next_tick = now + .005
        for key, group in list(self.groups.items()):
            if all_groups or now-group[2] >= self.seconds: self.flush(key)


def open_regular(path):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('Tetragon input must be a regular JSONL file')
        return os.fdopen(fd,'rb')
    except BaseException:
        os.close(fd);raise


async def consume(engine, path, follow=False, from_end=False, duration=None, uid=None, include_args=True, window_ms=0, service_name=None):
    outgoing=deque()
    coalescer=Coalescer(engine,window_ms,emit=outgoing.append)
    adapter=Adapter(uid,include_args)
    stream=open_regular(path)
    end=time.monotonic()+duration if duration is not None else float('inf')
    discarding=False
    pending=b''
    next_health=0
    async def drain(timeout=None):
        deadline=time.monotonic()+timeout if timeout is not None else float('inf')
        started=None
        while outgoing:
            if engine.queue.full() and time.monotonic()<deadline:
                if started is None:
                    started=time.monotonic();engine.stats['tetragon_backpressure_waits']+=1
                await asyncio.sleep(.005)
                continue
            engine.submit(outgoing.popleft())
        if started is not None:
            engine.stats['tetragon_backpressure_ms']+=round((time.monotonic()-started)*1000,2)
    def accept(line):
        if not line.strip():return
        engine.stats['tetragon_lines']+=1
        try:
            raw=json.loads(line)
            if isinstance(raw,dict) and 'rate_limit_info' in raw:
                count=raw['rate_limit_info'].get('number_of_dropped_process_events',0)
                if isinstance(count,str) and count.isdigit(): count=int(count)
                if type(count) is int and count>=0:
                    if count: engine.stats['log_errors']+=1
                    engine.stats['tetragon_export_lost']+=count
                return
            if isinstance(raw,dict) and 'process_throttle' in raw:
                engine.stats['tetragon_throttle_notifications']+=1
                engine.stats['log_errors']+=1
                return
            event=adapter.parse(raw)
        except (ValueError,TypeError,OverflowError,RecursionError):
            engine.stats['tetragon_invalid']+=1
            engine.stats['trace_parser_skipped']+=1
            return
        if event is None:
            engine.stats['tetragon_filtered_or_unsupported']+=1;return
        # Exclude MOP itself to avoid classification feedback from its own activity.
        from .pipeline_identity import is_monitor
        if event.pid==os.getpid() or is_monitor(event.pid):
            engine.stats['tetragon_self_filtered']+=1;return
        from .pipeline_identity import is_telemetry_write
        if is_telemetry_write(event):
            engine.stats['tetragon_telemetry_filtered']+=1;return
        engine.stats['tetragon_events']+=1
        coalescer.offer(event)
    try:
        if from_end:stream.seek(0,2)
        while time.monotonic()<end:
            coalescer.tick()
            await drain()
            if service_name and time.monotonic() >= next_health:
                health=await asyncio.create_subprocess_exec('systemctl','is-active','--quiet',service_name)
                if await health.wait(): raise RuntimeError('Tetragon collector stopped')
                next_health=time.monotonic()+5
            chunk=stream.read(16384)
            if chunk:
                pending+=chunk
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    if not discarding:
                        if len(line)<=LIMIT:accept(line)
                        else:engine.stats['tetragon_oversized']+=1;engine.stats['trace_parser_skipped']+=1
                    discarding=False
                    await drain()
                if len(pending)>LIMIT:
                    if not discarding:engine.stats['tetragon_oversized']+=1;engine.stats['trace_parser_skipped']+=1
                    pending=b'';discarding=True
                await asyncio.sleep(0)
                continue
            if not follow:
                if pending and not discarding:accept(pending)
                coalescer.tick(all_groups=True)
                await drain()
                return 0
            try:
                current=os.stat(path,follow_symlinks=False);opened=os.fstat(stream.fileno())
                rotated=(current.st_dev,current.st_ino)!=(opened.st_dev,opened.st_ino)
                truncated=current.st_size<stream.tell()
                if rotated or truncated:
                    replacement=open_regular(path)
                    stream.close();stream=replacement
                    pending=b'';discarding=False
                    engine.stats['tetragon_source_resets']+=1
            except FileNotFoundError:
                pass
            await asyncio.sleep(.1)
        return 0
    except Exception:
        engine.stats['tetragon_source_errors']+=1
        engine.stats['log_errors']+=1
        raise
    finally:
        stream.close()
        coalescer.tick(all_groups=True)
        await drain(timeout=1)
