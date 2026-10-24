from __future__ import annotations

import asyncio
import json
import os
import pwd
import re
import shutil
import sys
import tempfile
from pathlib import Path

from .core import Event
from .proc import snapshot
from .processes import terminate_group

TRACE_PATTERN = re.compile(r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(\d+\.\d+)\s+([\w]+)\(")


def parse_strace(line, include_details=False):
    match = TRACE_PATTERN.match(line)
    if not match:
        return None
    from .trace_evidence import syscall_boundary
    close=syscall_boundary(line,match.end())
    result = re.match(r"\s+=\s+(-?0x[\da-f]+|-?\d+|\?)(?:\s+([A-Z][A-Z0-9_]+))?", line[close+1:]) if close is not None else None
    metadata = {"trace_timestamp": float(match.group(3)), "arguments": "omitted",
                "result": result.group(1) if result else "pending_or_unavailable",
                "identity_note": "TID only; TGID unknown"}
    if result and result.group(2):
        metadata["errno"] = result.group(2)
    if include_details:
        from .trace_evidence import safe_arguments
        arguments=line[match.end():close] if close is not None else line[match.end():].split('<unfinished ...>',1)[0]
        sanitized=safe_arguments(arguments)
        metadata['arguments']=sanitized[:4096]
        metadata['arguments_truncated']=len(sanitized)>4096 or '...' in arguments
        metadata['source']='Decoded kernel syscall observation from private strace output'
        metadata['outcome']='unknown' if not result or result.group(1)=='?' else 'failed' if result.group(1).startswith('-') else 'completed'
        metadata['limitations']='Decoded paths/addresses/results, not business authorization or complete dataflow. Payload syscalls are rendered raw.'
    return Event(match.group(4), "strace", tid=int(match.group(1) or match.group(2) or 0),
                 metadata=metadata, timestamp=float(match.group(3)))


def resolve_trace_identity(event):
    """Best-effort live identity enrichment; missing data never becomes a guessed PID."""
    if not event.tid:
        return False
    try:
        task = Path("/proc") / str(event.tid)
        tgid = next(int(line.split()[1]) for line in (task / "status").read_text().splitlines()
                    if line.startswith("Tgid:"))
        thread_raw = (task / "stat").read_text()
        leader_raw = (Path("/proc") / str(tgid) / "stat").read_text()
        event.pid = tgid
        event.comm = thread_raw[thread_raw.index("(") + 1:thread_raw.rindex(")")]
        event.metadata["thread_start_ticks"] = int(thread_raw[thread_raw.rindex(")") + 2:].split()[19])
        event.metadata["start_ticks"] = int(leader_raw[leader_raw.rindex(")") + 2:].split()[19])
        event.metadata["identity_note"] = "best-effort live proc lookup; not atomic with trace event"
        return True
    except (OSError, ValueError, IndexError, StopIteration):
        return False


async def trace_command(engine, command, scope, duration, privileged=False, include_details=False, attach_pid=None):
    if not shutil.which("strace"):
        raise ValueError("strace is unavailable; install it or use watch/replay")
    if not command and attach_pid is None:
        raise ValueError("a command or --pid is required")
    if command and attach_pid is not None:
        raise ValueError("choose either a launched command or --pid")
    if attach_pid == os.getpid():
        raise ValueError("MOP cannot attach to its own process")
    if attach_pid is not None and attach_pid <= 0:
        raise ValueError("attach PID must be positive")
    from .paths import runtime_root
    runtime = runtime_root()
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    trace_set = "all" if scope == "all" else "execve,execveat,open,openat,openat2,creat,close,connect,bind,listen,accept,accept4,socket,getsockname,getpeername,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,truncate,ftruncate,link,linkat,symlink,symlinkat,clone,clone3,fork,vfork,setuid,setgid,setreuid,setregid,setresuid,setresgid,capset,mprotect,ptrace"
    prefix = ["sudo", "-n", "strace"] if privileged else ["strace"]
    if privileged and attach_pid is None:prefix += ["-u",pwd.getpwuid(os.getuid()).pw_name]
    if attach_pid is not None:
        from .evidence import process_identity
        attached_generation=process_identity(attach_pid)[0]
    from .trace_evidence import TraceDecoder
    decoder=TraceDecoder(parse_strace,include_details)
    captured=[]
    def submit_event(event):
        if attach_pid is None:
            engine.submit(event)
        elif len(captured)<4096:
            event.metadata['capture_mode']='Buffered during attachment; classified only after detach'
            captured.append(event)
        else:
            engine.stats['trace_capture_overflow']+=1

    # Separate tracer channel: workload stderr must not become trusted trace events.
    with tempfile.TemporaryDirectory(prefix="trace-", dir=runtime) as tmp:
        fifo = Path(tmp) / "events.pipe"
        os.mkfifo(fifo, 0o600)
        read_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        keep_fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        proc, reader = None, None
        engine.stats["trace_parser_skipped"] = 0

        async def read():
            pending = b""
            while True:
                try:
                    chunk = os.read(read_fd, 65536)
                except BlockingIOError:
                    await asyncio.sleep(.005)
                    continue
                if not chunk:
                    if pending:
                        engine.stats["trace_partial_lines"] += 1
                    return
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    text = line.decode(errors="replace")
                    if len(line) > 8192:
                        engine.stats["trace_oversized_lines"] += 1
                        continue
                    event = decoder.feed(text)
                    if event:
                        if not resolve_trace_identity(event):
                            engine.stats["identity_resolution_unavailable"] += 1
                        submit_event(event)
                    elif "<unfinished ...>" in text:
                        engine.stats["trace_unfinished_lines"] += 1
                    elif "<..." in text and "resumed>" in text:
                        engine.stats["trace_resumed_lines"] += 1
                    else:
                        engine.stats["trace_parser_skipped"] += 1
                if len(pending) > 8192:
                    engine.stats["trace_oversized_lines"] += 1
                    pending = b""
                await asyncio.sleep(0)

        try:
            detail_flags = ["-yy","-s","256","-e","raw=read,write,readv,writev,pread64,pwrite64,preadv,pwritev,sendto,recvfrom,sendmsg,recvmsg,sendmmsg,recvmmsg,getrandom,getxattr,lgetxattr,fgetxattr"] if include_details else ["-e","raw=all"]
            target_flags = ["-p",str(attach_pid)] if attach_pid is not None else ["--",*command]
            proc = await asyncio.create_subprocess_exec(
                *prefix, "-f", "-ttt", "-qq", "-o", str(fifo),
                "-e", "trace=" + trace_set, *detail_flags, *target_flags,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True)
            if attach_pid is not None and process_identity(attach_pid)[0]!=attached_generation:
                raise ValueError("Target identity changed before attachment")
            reader = asyncio.create_task(read())
            try:
                code = await asyncio.wait_for(proc.wait(), duration)
                engine.stats["trace_exit_code"] = code
                return code
            except asyncio.TimeoutError:
                engine.stats["trace_duration_expired"] += 1
                return 124
            finally:
                if proc.returncode is None:
                    await terminate_group(proc, privileged)
        finally:
            if proc is not None and proc.returncode is None:
                await terminate_group(proc, privileged)
            os.close(keep_fd)
            if reader:
                try:
                    await asyncio.wait_for(reader, 2)
                except asyncio.TimeoutError:
                    engine.stats["trace_reader_drain_timeout"] += 1
                finally:
                    if not reader.done():
                        reader.cancel()
                    await asyncio.gather(reader, return_exceptions=True)
            for event in decoder.finish():
                resolve_trace_identity(event)
                submit_event(event)
            engine.stats['trace_unmatched_resumes']=decoder.unmatched_resumes
            engine.stats['trace_pending_evicted']=decoder.evicted
            os.close(read_fd)
            # In particular, attaching to the classifier service must not recursively
            # classify its own inference handling while the tracer is active.
            for event in captured:
                engine.submit(event)
                await asyncio.sleep(0)


async def replay(engine, path):
    with open(path) as stream:
        number = 0
        while True:
            line = stream.readline(16385)
            if not line:
                return
            number += 1
            if len(line) > 16384:
                raise ValueError("replay line exceeds limit at line " + str(number))
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                # Audit logs can be replayed as well as raw event fixtures.
                value = value.get("event", value) if isinstance(value, dict) else value
                event = Event.from_dict(value)
            except (ValueError, TypeError, KeyError):
                raise ValueError("invalid event at replay line " + str(number)) from None
            if engine.queue.full(): engine.stats["replay_backpressure_waits"] += 1
            while engine.queue.full(): await asyncio.sleep(.005)
            engine.submit(event)
            await asyncio.sleep(0)


async def proc_watch(engine, duration, interval, all_users=False, threads=False, render=None, iterations=None, user_filter=None, pid_filter=(), view_all_users=False):
    end = asyncio.get_running_loop().time() + duration if duration is not None else float("inf")
    previous = {}
    samples = 0
    previous_at = asyncio.get_running_loop().time()
    previous_system = {}
    from .meters import read_system, cpu_percent
    initialized = False
    reviewed = {}
    while asyncio.get_running_loop().time() < end:
        rows, denied = await asyncio.to_thread(snapshot, all_users=all_users or view_all_users, threads=threads)
        if user_filter:
            rows = [r for r in rows if user_filter in {r.get('user'), str(r.get('uid'))}]
        if pid_filter:
            rows = [r for r in rows if r['pid'] in pid_filter]
        system = await asyncio.to_thread(read_system)
        system['cpu_percent'] = cpu_percent(system, previous_system)
        previous_system = system
        sample_at = asyncio.get_running_loop().time()
        for row in rows:
            old = previous.get((row['pid'],row['tid'],row['start_ticks']))
            row['cpu'] = max(0,100*(row['ticks']-old['ticks'])/os.sysconf('SC_CLK_TCK')/max(sample_at-previous_at,.001)) if old else 0
            row['memory_percent'] = row['rss_mb']*1048576/system['memory_total']*100 if system.get('memory_total') else 0
        previous_at = sample_at
        engine.process_metrics = system
        engine.retain_visible_identities(rows)
        engine.stats["proc_inaccessible"] = denied
        current = {(r["pid"], r["tid"], r["start_ticks"]): r for r in rows}
        now = asyncio.get_running_loop().time()
        due = {key for key in current if engine.review_interval > 0 and now - reviewed.get(key, -float("inf")) >= engine.review_interval}
        for key in (current.keys() - reviewed.keys()) | due:
            r = current[key]
            from .pipeline_identity import is_monitor
            if r["pid"] == os.getpid() or is_monitor(r["pid"]) or (view_all_users and not all_users and r.get("uid") != os.getuid()):
                continue
            accepted = engine.submit(Event("process_review" if key in previous else "task_discovered" if initialized else "task_present",
                                "proc-poll", r["pid"], r["tid"], r["comm"],
                                metadata={"ppid": r["ppid"], "start_ticks": r["start_ticks"],
                                          "uid": r["uid"], "not_a_syscall": True}))
            if accepted: reviewed[key] = now
        reviewed = {key: value for key, value in reviewed.items() if key in current}
        previous, initialized = current, True
        if render:
            render(rows, engine)
        samples += 1
        if iterations is not None and samples >= iterations: break
        await asyncio.sleep(interval)
