"""Explicit user-requested process controls; never invoked by model verdicts."""
import os
from pathlib import Path
import select
import signal


def read_identity(pid):
    path = Path('/proc') / str(pid)
    text = (path / 'stat').read_text()
    fields = text[text.rindex(')') + 2:].split()
    return int(fields[19]), path.stat().st_uid


def apply_action(row, action, value):
    pid = row['pid']
    if pid <= 1 or pid == os.getpid() or row['tid'] != pid:
        raise ValueError('Select a process leader other than PID 1 or MOP itself')
    if action not in {'signal', 'nice'}:
        raise ValueError('Unknown process action')
    value = int(value)
    if action == 'signal' and value not in {signal.SIGTERM, signal.SIGKILL, signal.SIGINT, signal.SIGSTOP, signal.SIGCONT, signal.SIGHUP}:
        raise ValueError('Allowed signals: 1, 2, 9, 15, 18, 19')
    if action == 'nice' and not -20 <= value <= 19:
        raise ValueError('Nice value must be -20..19')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('Process controls require pidfd support')
    fd = os.pidfd_open(pid)
    try:
        start, uid = read_identity(pid)
        if start != row.get('start_ticks'):
            raise ValueError('Process identity changed; refresh the selection')
        if os.geteuid() != 0 and uid != os.geteuid():
            raise PermissionError('Process belongs to another user')
        poll = select.poll(); poll.register(fd, select.POLLIN)
        if poll.poll(0):
            raise ProcessLookupError('Process already exited')
        if action == 'signal':
            signal.pidfd_send_signal(fd, value)
            return 'Sent %s to PID %d' % (signal.Signals(value).name, pid)
        # setpriority has no pidfd variant: verify identity immediately before
        # the syscall. Kernel permissions still apply; no sudo escalation.
        if read_identity(pid)[0] != start:
            raise ValueError('Process identity changed')
        os.setpriority(os.PRIO_PROCESS, pid, value)
        return 'Set PID %d nice to %d' % (pid, os.getpriority(os.PRIO_PROCESS, pid))
    finally:
        os.close(fd)


def command_line(row):
    """Bounded, redacted display text; unavailable/reused PIDs keep comm only."""
    from .content import command_arguments
    import json
    try:
        if read_identity(row['pid'])[0] != row['start_ticks']:
            return row['comm']
        with (Path('/proc') / str(row['pid']) / 'cmdline').open('rb') as f:
            raw = f.read(16385)
        if len(raw) > 16384 or read_identity(row['pid'])[0] != row['start_ticks']:
            return row['comm']
        argv = [a.decode('utf-8', 'replace') for a in raw.split(b'\0') if a]
        if not argv: return row['comm']
        evidence = command_arguments(argv)
        return evidence['text'] if evidence['truncated'] else ' '.join(json.loads(evidence['text']))
    except (OSError, ValueError, IndexError):
        return row['comm']
