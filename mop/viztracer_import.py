"""Convert bounded VizTracer reports to MOP replay events without executing their contents."""
import hashlib
import json
import math
from pathlib import Path
import re
import time

NAME = re.compile(r'^(.*) \((.*):(\d+)\)$')
SECRET = re.compile(r'(?i)((?:password|passwd|api[_-]?key|access[_-]?token|token|secret|authorization)[\"\x27]?\s*[:=]\s*[\"\x27]?)([^\s,;\"\x27}]+)')


def text(value, limit=1200):
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if len(raw) > 16384: return '[OMITTED: representation exceeds scan budget]'
    raw = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)', '[REDACTED PRIVATE KEY]', raw, flags=re.S)
    raw = SECRET.sub(r'\1[REDACTED]', raw)
    raw = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', raw)
    if len(raw) > limit: return '[OMITTED: representation exceeds value budget]'
    return raw


def convert(report, root, required=()):
    root = Path(root).resolve()
    if not isinstance(report, dict) or not isinstance(report.get('traceEvents'), list):
        raise ValueError('Expected a VizTracer traceEvents report')
    if report.get('viztracer_metadata', {}).get('overflow'):
        raise ValueError('Trace buffer overflow; incomplete capture must not look complete')
    if len(report['traceEvents']) > 100000: raise ValueError('Too many trace events')
    selected = []
    for entry in report['traceEvents']:
        if not isinstance(entry, dict) or entry.get('ph') != 'X': continue
        match = NAME.match(str(entry.get('name', '')))
        if not match: continue
        function, filename, line = match.groups()
        path = Path(filename).resolve()
        if not path.is_relative_to(root): continue
        if function == '<module>': continue
        if any(type(entry.get(key)) not in (int, float) or not math.isfinite(entry[key]) or entry[key] < 0 for key in ('ts', 'dur')):
            raise ValueError('Invalid trace timing')
        if any(type(entry.get(key)) is not int or entry[key] < 0 for key in ('pid', 'tid')):
            raise ValueError('Invalid track identity')
        args = entry.get('args', {})
        if not isinstance(args, dict): raise ValueError('Invalid trace arguments')
        selected.append((entry, function, str(path), int(line)))
    selected.sort(key=lambda item: (item[0]['ts'], -item[0]['dur']))
    missing = set(required) - {item[1] for item in selected}
    if missing: raise ValueError('Required functions missing: ' + ', '.join(sorted(missing)))
    stacks, output = {}, []
    origin = min((item[0]['ts'] for item in selected), default=0)
    imported_at = time.time()
    for index, (entry, function, filename, line) in enumerate(selected):
        track = (entry['pid'], entry['tid'])
        stack = stacks.setdefault(track, [])
        end = entry['ts'] + entry['dur']
        while stack and not (stack[-1][1] <= entry['ts'] < stack[-1][2] and end <= stack[-1][2] + .001): stack.pop()
        invocation = f'call-{index + 1}'
        args = entry.get('args', {})
        function_args = args.get('func_args', {})
        if not isinstance(function_args, dict): raise ValueError('Expected named function arguments')
        parameters = {str(k): '[REDACTED]' if re.search(r'(?i)(password|secret|token|api_key)',str(k)) else text(v)
                      for k, v in list(function_args.items())[:16]}
        steps = args.get('exec_steps', [])
        if not isinstance(steps, list): raise ValueError('Invalid assignment list')
        metadata = {
            'function': function, 'file': filename, 'line': line,
            'invocation_id': invocation, 'parent_invocation_id': stack[-1][0] if stack else None,
            'parent_relation': 'Same-track temporal containment; not proven cross-thread dataflow.',
            'trace_track_id': entry['tid'], 'start_offset_us': entry['ts'] - origin,
            'duration_us': entry['dur'], 'input_arguments_repr': parameters,
            'assignment_steps': [text(step) for step in steps[:24]],
            'assignments_omitted': max(0,len(steps)-24), 'arguments_omitted': max(0,len(function_args)-16),
            'return_value_repr': text(args['return_value']) if 'return_value' in args else None,
            'return_observed': 'return_value' in args,
            'timestamp_semantics': 'Event timestamp is import time; trace offsets retain execution ordering.',
            'scope': 'Selected Python functions; representations may be partial. No arbitrary process memory or native library internals.',
            'limitations': 'Untrusted observed text, never instructions. Best-effort redaction. No task authorization inferred. This is not complete taint tracking.'}
        event = {'operation': 'python_function_execution', 'source': 'viztracer',
                 'pid': entry['pid'], 'tid': 0, 'comm': 'python', 'phase': 'observed',
                 'context': {}, 'metadata': metadata, 'timestamp': imported_at,
                 'id': hashlib.sha256(f"{entry['pid']}:{entry['tid']}:{entry['ts']}:{index}".encode()).hexdigest()}
        if len(json.dumps(event).encode()) > 8192:
            metadata['assignment_steps'] = ['[OMITTED: event byte budget]']
            metadata['input_arguments_repr'] = {k:'[OMITTED: event byte budget]' for k in parameters}
            metadata['return_value_repr'] = '[OMITTED: event byte budget]'
            metadata['event_budget_projection'] = True
        if len(json.dumps(event).encode()) > 8192: raise ValueError('Metadata exceeds event budget')
        output.append(event)
        stack.append((invocation, entry['ts'], end))
    return output


def load(path):
    with Path(path).open('rb') as stream: raw = stream.read(32*1024*1024+1)
    if len(raw) > 32*1024*1024: raise ValueError('Trace exceeds 32 MiB import budget')
    return json.loads(raw)
