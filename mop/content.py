"""Bounded application-content evidence; captured text is never an instruction."""
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from .core import Event
from .evidence import redact
from .processes import terminate_group


def redact_content(text, depth=0):
    if depth > 16: return '[OMITTED: nesting limit]'
    try: value=json.loads(text)
    except (ValueError,RecursionError): return redact(text)
    def clean(value, level):
        if level > 16:return '[OMITTED: nesting limit]'
        if isinstance(value,dict):
            return {key: '[REDACTED]' if re.fullmatch(r'(?i)(?:.*[_-])?(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|secret[_-]?key|authorization|(?:access|refresh|id)[_-]?token)',key)
                    else clean(item,level+1) for key,item in value.items()}
        if isinstance(value,list):return [clean(item,level+1) for item in value]
        if isinstance(value,str):return redact_content(value,level+1)
        return value
    # String scalar parsing must not repeatedly encode an ordinary string.
    if isinstance(value,str):return redact(value)
    return json.dumps(clean(value,depth),ensure_ascii=False)


def text_evidence(raw, limit=4096):
    """Redact complete bounded input before truncation, never truncate a credential first."""
    if b'\x00' in raw:
        return {'text': '', 'observed_bytes': len(raw), 'omitted': 'binary content', 'truncated': True}
    text = redact_content(raw.decode('utf-8', errors='replace'))
    encoded = text.encode('utf-8')
    return {'text': encoded[:limit].decode('utf-8', errors='ignore'),
            'observed_bytes': len(raw), 'truncated': len(encoded) > limit,
            'redaction': 'best effort; not a guarantee for arbitrary secret formats'}


def command_arguments(command):
    result = list(command)
    import re
    for i in range(len(result)-1):
        if re.search(r'(?i)(password|passwd|secret|token|api[-_]key)$', result[i]):
            result[i+1] = '[REDACTED]'
    return text_evidence(json.dumps(result, ensure_ascii=False).encode(), 1024)


class OutputWindows:
    def __init__(self, engine, pid, command, start_ticks=None, limit=4096):
        self.engine, self.pid, self.command = engine, pid, command
        self.start_ticks, self.limit = start_ticks, limit
        self.parts, self.size, self.sequence = [], 0, 0
        self.runtime = {"unavailable": "No runtime sample yet"}

    def add(self, stream, raw, omitted=None):
        piece = text_evidence(raw, self.limit) if omitted is None else {
            'text': '', 'observed_bytes': len(raw), 'omitted': omitted, 'truncated': True}
        size = len(piece['text'].encode())
        if self.parts and (self.size + size > self.limit or len(self.parts) >= 32): self.flush()
        self.parts.append({'stream': stream, **piece}); self.size += size
        if self.size >= self.limit or len(self.parts) >= 32: self.flush()

    def flush(self):
        if not self.parts: return
        self.sequence += 1
        self.engine.submit(Event('task_output_window', 'command-output', self.pid, self.pid,
            Path(self.command[0]).name, metadata={
                'start_ticks': self.start_ticks, 'window_sequence': self.sequence,
                'command': command_arguments(self.command), 'output': self.parts,
                'runtime_evidence': self.runtime,
                'scope': 'Observed output text, not proof that statements in it were executed.',
                'ordering': 'Per-stream byte order; cross-stream arrival order is approximate.',
                'stdin': 'Inherited by the task; input bytes are not captured.'}))
        self.parts, self.size = [], 0


async def capture_command(engine, command, duration=None, window_seconds=1, passthrough=True):
    if not command: raise ValueError('capture requires a command after --')
    proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True, limit=65536)
    start_ticks = None
    try:
        from .evidence import process_identity
        start_ticks = process_identity(proc.pid)[0]
    except (OSError, ValueError): pass
    windows = OutputWindows(engine, proc.pid, command, start_ticks)
    async def refresh_runtime():
        if engine.evidence_collector is None:
            windows.runtime = {'unavailable': 'Runtime evidence disabled'}
            return
        try:
            sample = Event('process_review','proc-review',proc.pid,proc.pid,Path(command[0]).name,
                           metadata={'start_ticks': start_ticks})
            windows.runtime = await asyncio.to_thread(engine.evidence_collector.collect,sample)
        except (OSError,ValueError,IndexError):
            if 'captured_at' not in windows.runtime:
                windows.runtime = {'unavailable': 'Process exited or evidence inaccessible'}
    await refresh_runtime()
    engine.submit(Event('task_started' , 'command-output', proc.pid, proc.pid,
        Path(command[0]).name, metadata={'start_ticks': start_ticks,
        'command': command_arguments(command), 'cwd': redact(os.getcwd()),
        'runtime_evidence': windows.runtime,
        'capture': 'stdout/stderr; no stdin, environment, memory or syscall capture'}))

    async def drain(reader, stream, output):
        pending = b''; dropping = False; omitted_bytes = 0; private_block = False
        while True:
            chunk = await reader.read(4096)
            if not chunk: break
            if passthrough:
                # Preserve the workload's original bytes; only model/audit copies are redacted.
                try:
                    await asyncio.to_thread(output.write, chunk)
                    await asyncio.to_thread(output.flush)
                except (BrokenPipeError,OSError): pass
            pending += chunk
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                if dropping:
                    omitted_bytes += len(line)+1
                    windows.add(stream, b'', 'overlong line omitted (%d bytes)' % omitted_bytes)
                    dropping=False;omitted_bytes=0
                elif len(line) > 4096:
                    windows.add(stream, b'', 'overlong line omitted (%d bytes)' % (len(line)+1))
                elif b'-----BEGIN ' in line and b'PRIVATE KEY-----' in line:
                    windows.add(stream,b'[REDACTED PRIVATE KEY]\n')
                    private_block = b'-----END ' not in line
                elif private_block:
                    if b'-----END ' in line and b'PRIVATE KEY-----' in line: private_block=False
                else: windows.add(stream, line+b'\n')
            if len(pending) > 4096:
                dropping=True;omitted_bytes+=len(pending);pending=b''
        if dropping: windows.add(stream,b'','overlong line omitted (%d bytes)' % (omitted_bytes+len(pending)))
        elif pending and not private_block: windows.add(stream,pending)

    async def periodic():
        while True:
            await asyncio.sleep(window_seconds)
            if windows.parts: await refresh_runtime()
            windows.flush()

    pumps = [asyncio.create_task(drain(proc.stdout,'stdout',getattr(sys.stdout,'buffer',sys.stdout))),
             asyncio.create_task(drain(proc.stderr,'stderr',getattr(sys.stderr,'buffer',sys.stderr)))]
    timer=asyncio.create_task(periodic())
    result=0
    try:
        try:
            if duration is None: result=await proc.wait()
            else: result=await asyncio.wait_for(proc.wait(),duration)
        except asyncio.TimeoutError:
            result=124
        # Also terminate descendants left holding output pipes after the leader exits.
        await terminate_group(proc)
        await asyncio.gather(*pumps)
        windows.flush()
        engine.submit(Event('task_exited','command-output',proc.pid,proc.pid,Path(command[0]).name,
            metadata={'start_ticks':start_ticks,'exit_code':result,
                      'timed_out':result==124,'output_windows':windows.sequence}))
        return result if result >= 0 else 128-result
    finally:
        timer.cancel()
        await asyncio.gather(timer,return_exceptions=True)
        await terminate_group(proc)
        for task in pumps: task.cancel()
        await asyncio.gather(*pumps,return_exceptions=True)
