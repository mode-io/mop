"""Bounded, read-only process evidence. Never consume pipes, sockets or terminals."""
import os
import re
import json
import stat
import time
import threading
from collections import OrderedDict
from pathlib import Path

SENSITIVE = re.compile(r"(^|[/_.-])(env|ssh|aws|credentials?|secrets?|tokens?|id_rsa|id_ed25519)([/_.-]|$)", re.I)
SECRET = re.compile(r"(?i)((?:password|passwd|api[_-]?key|access[_-]?token|token|secret|authorization)\s*[=:]\s*)([^\s,;]+)")

def redact(text):
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[REDACTED PRIVATE KEY]", text, flags=re.S)
    text = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = SECRET.sub(r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{12,})\b", "[REDACTED TOKEN]", text)
    text = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", text)
    text = re.sub(r'(?m)^[A-Za-z0-9+/=]{48,}$', '[REDACTED POSSIBLE KEY MATERIAL]', text)
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32 and ord(c) != 127)


def read_small(path, limit=4096):
    with open(path, 'rb') as stream:
        return stream.read(limit).decode('utf-8', errors='replace')


def process_identity(pid, root='/proc', tid=None):
    path = Path(root) / str(pid)
    if tid is not None and tid != pid:
        path = path / 'task' / str(tid)
    raw = read_small(path / 'stat')
    end = raw.rindex(')')
    fields = raw[end + 2:].split()
    return int(fields[19]), raw[raw.index('(') + 1:end], fields


def tail_file(path, roots=None, via_fd=False, limit=1024, owned_only=False):
    """Open a private read offset; confirm regular file and permitted resolved target."""
    expected_file = os.stat(path) if via_fd else None
    if via_fd:
        target = os.readlink(path)
        if not target.startswith('/'):
            return {'status': 'skipped_non_regular'}
        path = Path(target)
    if SENSITIVE.search(str(path)):
        return {'status': 'skipped_sensitive_path'}
    if not stat.S_ISREG(os.lstat(path).st_mode):
        return {'status': 'skipped_non_regular'}
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return {'status': 'skipped_non_regular'}
        if expected_file is not None and (info.st_dev,info.st_ino)!=(expected_file.st_dev,expected_file.st_ino):
            return {'status': 'skipped_changed_output_identity'}
        if owned_only and info.st_uid != os.getuid():
            return {'status': 'skipped_other_owner'}
        actual = Path(os.readlink('/proc/self/fd/' + str(fd)))
        if SENSITIVE.search(str(actual)):
            return {'status': 'skipped_sensitive_path'}
        if roots is not None and not any(actual.is_relative_to(root) for root in roots):
            return {'status': 'skipped_outside_output_roots'}
        size = info.st_size
        offset = max(0, size - limit)
        os.lseek(fd, offset, os.SEEK_SET)
        raw = os.read(fd, limit)
        if b'\x00' in raw:
            return {'status': 'skipped_binary'}
        # A tail can begin in the middle of a secret; discard its partial first line.
        if offset:
            raw = raw.split(b'\n', 1)[1] if b'\n' in raw else b''
        from .content import redact_content
        text=redact(raw.decode('utf-8', errors='replace'))
        safe_text='\n'.join(redact_content(line) for line in text.splitlines())
        if text.endswith('\n'):safe_text+='\n'
        return {'status': 'ok', 'tail': safe_text,
                'file_size': size, 'tail_limit': limit, 'truncated': offset > 0}
    finally:
        os.close(fd)


class EvidenceCollector:
    def __init__(self, root='/proc', logs=(), output_roots=(), include_args=True, budget=6000, auto_output=False, evidence_log=None):
        self.root = Path(root)
        self.logs = [Path(p).absolute() for p in logs]
        self.output_roots = [Path(p).resolve() for p in output_roots]
        self.include_args = include_args
        self.budget = budget
        from .system_facts import SystemFacts
        self.facts = SystemFacts(root, redact)
        self.auto_output, self.evidence_log = auto_output, evidence_log
        self.previous = OrderedDict()
        self.lock = threading.Lock()

    def collect(self, event):
        path = self.root / str(event.pid)
        expected = event.metadata.get('start_ticks')
        selected_tid=event.tid or event.pid
        start, name, fields = process_identity(event.pid, str(self.root), selected_tid)
        if start != expected:
            raise ValueError('Process identity changed before evidence collection')
        data = {'captured_at': time.time(), 'scope': 'system-derived process observations; no inferred task intent or business authorization',
                'identity': {'pid': event.pid, 'tid': selected_tid, 'start_ticks': start},
                'process': {'name': redact(name), 'state': fields[0], 'ppid': int(fields[1]),
                            'cpu_ticks': int(fields[11]) + int(fields[12]), 'start_ticks': start},
                'gaps': ['Credential environment variables and process memory contents excluded; only allowlisted runtime flags collected.',
                         'Procfs does not read pipe/terminal payloads; command/proxy capture is separate.',
                         'Redaction is best effort; observations are untrusted data.']}
        for link in ('exe', 'cwd'):
            try: data['process'][link] = redact(os.readlink(path / link))[:256]
            except OSError: data['gaps'].append(link + ': unavailable')
        identity_path=path if selected_tid==event.pid else path/'task'/str(selected_tid)
        data['sources']={'proc_directory':str(identity_path),'identity':'stat','security':'status','io':'io'}
        for filename, allowed in [('status', {'Uid','Gid','Groups','Threads','VmRSS','VmSize','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','TracerPid','NSpid','SigBlk','SigIgn','SigCgt'}),
                                  ('io', {'rchar','wchar','read_bytes','write_bytes','syscr','syscw'})]:
            try:
                data[filename] = {k: v.strip()[:128] for line in read_small(identity_path / filename).splitlines()
                                  if ':' in line for k, v in [line.split(':', 1)] if k in allowed}
            except OSError: data['gaps'].append(filename + ': unavailable')
        data['system'] = self.facts.collect(event.pid, self.include_args, selected_tid)
        # The rich system section replaces the previous 24-argument/16-descriptor snapshot.
        data['fds'] = []
        data['logs'] = []
        for logfile in self.logs:
            item = {'source': 'explicit_task_log', 'path': redact(str(logfile))[:256]}
            try: item.update(tail_file(logfile))
            except OSError: item['status'] = 'unavailable_or_symlink'
            data['logs'].append(item)
        if self.output_roots or self.auto_output:
            for number in (1, 2):
                item = {'source': 'stdout' if number == 1 else 'stderr'}
                try: item.update(tail_file(path / 'fd' / str(number), self.output_roots or None, via_fd=True, owned_only=not bool(self.output_roots)))
                except OSError: item['status'] = 'unavailable'
                data['logs'].append(item)
        else: data['gaps'].append('Regular stdout/stderr file tails disabled for this collector.')
        if process_identity(event.pid, str(self.root), selected_tid)[0] != start:
            raise ValueError('Process identity changed during evidence collection')
        sampled = time.monotonic()
        observed_files=sorted({item['target'] for item in data['system'].get('open_files',[]) if item['target'].startswith('/')})[:32]
        observed_sockets=sorted(json.dumps({key:row[key] for key in ('protocol','local','remote','path') if key in row},sort_keys=True) for row in data['system'].get('connections',[]))[:16]
        key = (event.pid, event.tid, start)
        with self.lock:
            previous = self.previous.get(key)
            current = {"at": sampled, "cpu_ticks": data['process']['cpu_ticks'],
                       "io": dict(data.get('io', {})), "files":observed_files,"sockets":observed_sockets,
                       "privileges":{key:data.get('status',{}).get(key) for key in ('Uid','Gid','CapEff','NoNewPrivs','Seccomp')},
                       "exe":data['process'].get('exe')}
            if previous:
                data['changes'] = {'elapsed_seconds': sampled - previous['at'],
                    'cpu_ticks_delta': max(0, current['cpu_ticks'] - previous['cpu_ticks']),
                    'io_delta': {k: max(0, int(v) - int(previous['io'][k]))
                        for k, v in current['io'].items() if k in previous['io'] and v.isdecimal() and previous['io'][k].isdecimal()}}
                data['changes'].update({
                    'newly_observed_file_targets':sorted(set(current['files'])-set(previous['files'])),
                    'no_longer_observed_file_targets':sorted(set(previous['files'])-set(current['files'])),
                    'newly_observed_socket_endpoints':[json.loads(row) for row in sorted(set(current['sockets'])-set(previous['sockets']))],
                    'no_longer_observed_socket_endpoints':[json.loads(row) for row in sorted(set(previous['sockets'])-set(current['sockets']))],
                    'privilege_changes':{key:{'before':previous['privileges'].get(key),'after':value} for key,value in current['privileges'].items() if previous['privileges'].get(key)!=value},
                    'executable_link_changed':current['exe']!=previous['exe'],
                    'scope':'Snapshot differences, not exact open/close/exec times or proof of dataflow. Comparison bounds: 32 file targets, 16 socket endpoints.'})
            else:
                data['gaps'].append('No prior runtime sample for change comparison.')
            self.previous[key] = current
            self.previous.move_to_end(key)
            while len(self.previous) > 4096:
                self.previous.popitem(last=False)
        data['evidence_sufficiency'] = {
            'status': 'limited',
            'basis': 'System facts do not establish business intent, authorization, or complete behavior.',
            'missing': ['Past file/network operations between snapshots', 'Kernel audit history unless tracing is explicitly enabled',
                        'Plaintext of encrypted traffic', 'Credential environment values and process memory contents', 'Business authorization and file sensitivity policy']}
        if self.evidence_log:
            with self.lock:
                self.evidence_log.write_record({'kind':'system_evidence','pid':event.pid,'tid':event.tid,
                    'event_id':event.id,'evidence':data})
        system=data['system']
        dropped={}
        prefix=str(self.root/str(event.pid))+'/'
        system['provenance']={key:value.removeprefix(prefix) for key,value in system.get('provenance',{}).items()}
        unix=[row for row in system.get('connections',[]) if row['protocol']=='unix']
        if len(unix)>2:
            system['connections']=[row for row in system['connections'] if row['protocol']!='unix']+unix[:2]
            dropped['unix_connections']=len(unix)-2
        for name,value in data.get('changes',{}).items():
            if isinstance(value,list) and len(value)>4:
                dropped['changes.'+name]=len(value)-4;data['changes'][name]=value[:4]
        files=system.get('open_files',[])
        # Rank only for evidence selection, never for category assignment.
        files.sort(key=lambda item:(not item.get('deleted'),item.get('access_mode') not in {'write','read_write'},item['fd']))
        if len(files)>8:
            dropped['open_files']=len(files)-8;system['open_files']=files[:8]
        for item in system.get('open_files',[]):
            if 'attributes' in item:
                item['attributes']={key:value for key,value in item['attributes'].items()
                                    if key in {'uid','gid','mode','size_bytes','inode','world_writable','setuid','setgid'}}
        if 'threads' in system:
            thread_data=system['threads'];details=thread_data.get('details',[])
            thread_data['observed_count']=len(details)
            if len(details)>4:
                thread_data['details']=sorted(details,key=lambda item:item['cpu_ticks'],reverse=True)[:4]
                dropped['thread_details']=len(details)-4
        for section,limit in [('ancestry',3),('children',8)]:
            if len(system.get(section,[]))>limit:
                dropped[section]=len(system[section])-limit;system[section]=system[section][:limit]
        if dropped:data['projection_omissions']=dropped;data['truncated_to_budget']=True
        # Prefer concrete connections and arguments over bulk maps/thread/resource detail.
        for name in ['limits','mappings','threads','cwd_attributes','open_files','uid_map','gid_map','cgroups','namespaces','runtime_environment','ancestry','children','gpu']:
            while len(json.dumps(data, ensure_ascii=False).encode()) > self.budget and name in system:
                value=system[name]
                if isinstance(value,list) and value:
                    value.pop();dropped[name]=dropped.get(name,0)+1
                    if not value:system.pop(name)
                else:system.pop(name);dropped[name]=dropped.get(name,0)+1
                data['truncated_to_budget']=True
                data['projection_omissions']=dropped
        while len(json.dumps(data, ensure_ascii=False).encode()) > self.budget:
            if data['logs']:
                data['logs'].pop(); dropped['log_entries']=dropped.get('log_entries',0)+1
                data['projection_omissions']=dropped;data['truncated_to_budget'] = True
            elif data['fds']:
                data['fds'].pop(); data['truncated_to_budget'] = True
            elif any(isinstance(value,list) and value for value in data.get('changes',{}).values()):
                for name,value in data['changes'].items():
                    if isinstance(value,list) and value:
                        value.pop();dropped['changes.'+name]=dropped.get('changes.'+name,0)+1;break
                data['projection_omissions']=dropped;data['truncated_to_budget']=True
            elif system.get('connections'):
                system['connections'].pop();dropped['connections']=dropped.get('connections',0)+1
                data['projection_omissions']=dropped;data['truncated_to_budget']=True
            elif system.get('arguments',{}).get('values'):
                system['arguments']['values'].pop(0);system['arguments']['truncated']=True
                dropped['arguments']=dropped.get('arguments',0)+1;data['projection_omissions']=dropped
                data['truncated_to_budget']=True
            elif system.get('provenance'):
                system['provenance']={};data['truncated_to_budget']=True
            elif system.get('coverage'):
                system['coverage']={'status':'details omitted to budget'};data['truncated_to_budget']=True
                if len(json.dumps(data,ensure_ascii=False).encode())>self.budget:system.pop('coverage')
            else:
                raise ValueError('Evidence exceeds budget')
        return data

    def close(self):
        if self.evidence_log:
            self.evidence_log.close()
            self.evidence_log = None
