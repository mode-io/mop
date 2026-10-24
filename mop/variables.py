"""Opt-in Python variable observations, not complete taint tracking or enforcement."""
import argparse
import ast
import asyncio
import json
import os
from pathlib import Path
import re
import runpy
import sys
import threading
import time
from dataclasses import asdict

from .content import redact_content
from .core import Event

SECRET = re.compile(r'(?i)(password|passwd|secret|token|api_?key|authorization|credential)')
LIMITATIONS = (
    'Opt-in target Python file and initiating thread only; native code, other files, '
    'threads and subprocess internals are not traced. Values are bounded observations. '
    'AST reads and call arguments are syntactic candidates, not proven taint or executed '
    'branches. Unchanged summaries do not prove unchanged objects. No business intent '
    'or authorization is inferred. Redaction is best effort. Review is after execution, '
    'not prevention.'
)


def describe(value, name='', depth=0):
    """Never invoke user-defined repr, properties, iterators or serialization hooks."""
    kind = type(value)
    if SECRET.search(name):
        return {'type': kind.__name__, 'value': '[REDACTED]'}
    if kind in (str, bytes):
        if len(value) > 2048:
            return {'type': kind.__name__, 'length': len(value), 'omitted': 'value exceeds 2048 units'}
        if kind is bytes:
            return {'type': 'bytes', 'length': len(value), 'omitted': 'binary value'}
        return {'type': 'str', 'length': len(value), 'value': redact_content(value)}
    if kind in (int, float, bool, type(None)):
        if kind is int and value.bit_length() > 256:
            return {'type': 'int', 'omitted': 'large integer'}
        return {'type': kind.__name__, 'value': str(value)}
    if kind in (list, tuple, dict) and depth < 2:
        if kind is dict:
            items = []
            for i, (key, item) in enumerate(value.items()):
                if i == 8: break
                label = key if type(key) is str and len(key) <= 80 else '<non-text-key>'
                items.append({'key': label, 'value': describe(item, label, depth + 1)})
        else:
            items = [describe(item, '', depth + 1) for item in value[:8]]
        return {'type': kind.__name__, 'length': len(value), 'items': items, 'truncated': len(value) > 8}
    return {'type': kind.__name__, 'omitted': 'opaque object; no user code invoked'}


def call_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return call_name(node.value) + '.' + node.attr
    return '<dynamic-call>'


class VariableTrace:
    def __init__(self, path, max_events=256):
        self.path = str(Path(path).resolve())
        if not 1 <= max_events <= 4096: raise ValueError('max_events must be 1..4096')
        source = Path(self.path).read_text()
        if len(source) > 1024 * 1024: raise ValueError('target source exceeds 1 MiB')
        tree = ast.parse(source, filename=self.path)
        self.lines = {}
        for node in ast.walk(tree):
            line = getattr(node, 'lineno', 0)
            info = self.lines.setdefault(line, {'reads': set(), 'calls': []})
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load): info['reads'].add(node.id)
            if isinstance(node, ast.Call):
                names = sorted({n.id for arg in [*node.args, *(k.value for k in node.keywords)]
                                for n in ast.walk(arg) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)})
                info['calls'].append({'target': call_name(node.func), 'argument_names': names[:32]})
        self.max_events, self.events, self.dropped = max_events, [], 0
        self.frames, self.counter, self.errors = {}, 0, 0
        self.event_bytes, self.elapsed_ms = 0, 0
        self.stopped_reason = None

    def snapshot(self, frame):
        values = {}
        count = 0
        for name, value in frame.f_locals.items():
            if name.startswith('__'): continue
            count += 1
            if len(values) < 32: values[name] = describe(value, name)
        return values, max(0, count - len(values))

    def emit(self, frame, state, metadata):
        if len(self.events) >= self.max_events:
            self.dropped += 1
            self.stopped_reason = 'event or byte budget exhausted; remaining execution not observed'
            sys.settrace(None)
            return
        event = Event('python_variable_step', 'python-runtime', os.getpid(), threading.get_native_id(),
            'python', metadata={'file': self.path, 'function': frame.f_code.co_name,
            'invocation': state['id'], 'parent_invocation': state['parent'],
            **metadata, 'limitations': LIMITATIONS})
        size = len(json.dumps(event.payload(), ensure_ascii=False).encode())
        if self.event_bytes + size > 8 * 1024 * 1024:
            self.dropped += 1
            self.stopped_reason = 'event or byte budget exhausted; remaining execution not observed'
            sys.settrace(None)
            return
        self.event_bytes += size
        self.events.append(event)

    def flush(self, frame, state, outcome='advanced', returned=None, exception_type=None):
        if state['pending'] is None: return
        line, reads, calls = state['pending']
        now, omitted = self.snapshot(frame)
        changed = {}
        for name, value in now.items():
            if name not in state['values'] or value != state['values'][name]:
                state['versions'][name] = state['versions'].get(name, 0) + 1
                changed[name] = {'binding': f"{state['id']}:{name}:{state['versions'][name]}", 'observed': value}
        removed = sorted(set(state['values']) - set(now))
        # Absence under a local-count cap does not prove a binding was deleted.
        metadata = {'line': line, 'outcome': outcome, 'reads_before_line': reads,
                    'call_candidates': calls, 'changed_bindings': changed,
                    'no_longer_observed': removed, 'locals_omitted': omitted}
        if outcome == 'returned': metadata['return_value'] = describe(returned)
        if exception_type: metadata['exception_type'] = exception_type
        self.emit(frame, state, metadata)
        state['values'], state['pending'] = now, None

    def trace(self, frame, event, arg):
        if self.stopped_reason or frame.f_code.co_filename != self.path: return None
        try:
            key = id(frame)
            if event == 'call':
                self.counter += 1
                parent = self.frames.get(id(frame.f_back), {}).get('id')
                values, omitted = self.snapshot(frame)
                state = {'id': self.counter, 'parent': parent, 'values': values,
                         'versions': {name: 1 for name in values}, 'pending': None}
                self.frames[key] = state
                self.emit(frame, state, {'line': frame.f_lineno, 'outcome': 'entered',
                    'bindings': {name: {'binding': f'{self.counter}:{name}:1', 'observed': value}
                                 for name, value in values.items()}, 'locals_omitted': omitted})
            state = self.frames.get(key)
            if state is None: return self.trace
            if event == 'line':
                self.flush(frame, state)
                info = self.lines.get(frame.f_lineno, {'reads': [], 'calls': []})
                reads = {name: {'binding': f"{state['id']}:{name}:{state['versions'].get(name, 0)}",
                                'observed': state['values'][name]}
                         for name in sorted(info['reads']) if name in state['values']}
                state['pending'] = (frame.f_lineno, reads, info['calls'][:16])
            elif event == 'exception':
                self.flush(frame, state, 'exception', exception_type=arg[0].__name__)
            elif event == 'return':
                self.flush(frame, state, 'returned', arg)
                self.frames.pop(key, None)
        except Exception:
            self.errors += 1
        return self.trace

    def run(self, args=()):
        if sys.gettrace() is not None: raise RuntimeError('existing debugger/tracer must be disabled first')
        old_argv, old_path = sys.argv, sys.path[:]
        started = time.perf_counter()
        try:
            sys.argv = [self.path, *args]
            sys.path.insert(0, str(Path(self.path).parent))
            sys.settrace(self.trace)
            runpy.run_path(self.path, run_name='__main__')
        finally:
            sys.settrace(None)
            sys.argv, sys.path[:] = old_argv, old_path
            self.elapsed_ms = (time.perf_counter() - started) * 1000
            self.frames.clear()


def reviewable(event):
    return bool(event.metadata.get('call_candidates'))


async def review(events, config):
    from .classification import ClassificationProvider
    settings = json.loads(Path(config).read_text())
    task = dict(settings['classification'])
    task['prompt'] += (' For Python variable steps, assess how data is used at the observed operation, '
                       'not whether a variable name or value merely looks sensitive. AST call candidates '
                       'do not prove a call executed. An exception records failure at that line; '
                       'do not infer successful reading, writing or transmission from it.')
    provider = ClassificationProvider(settings['base_url'], task=task, timeout=30)
    selected = [event for event in events if reviewable(event)]
    records = {event.id: {'event': event.payload(), 'review_status': 'not_requested',
                         'review_reason': 'Binding or control-flow observation; no call candidate.'}
               for event in events}
    try:
        for offset in range(0, len(selected), 4):
            batch = selected[offset:offset + 4]
            try:
                verdicts = await provider.infer_batch(batch)
            except Exception as exc:
                for event in batch:
                    records[event.id] = {'event': event.payload(), 'request': provider.choice_payload(event),
                        'review_status': 'error', 'review_error': type(exc).__name__}
                continue
            for event, verdict in zip(batch, verdicts):
                records[event.id] = {'event': event.payload(), 'request': provider.choice_payload(event),
                                     'review_status': 'reviewed', 'verdict': asdict(verdict)}
    finally:
        await provider.aclose()
    return list(records.values())


def configure_parser(parser):
    parser.add_argument('--output', required=True, help='New private JSON report; existing files are refused')
    parser.add_argument('--max-events', type=int, default=256)
    parser.add_argument('--review-config', help='Opt-in local Jev classification after execution')
    parser.add_argument('script')
    parser.add_argument('script_args', nargs=argparse.REMAINDER)
    return parser


def execute(args):
    tracer = VariableTrace(args.script, args.max_events)
    # Reserve the report before executing the target, with restrictive permissions.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as report:
        status, failure = 0, None
        try:
            tracer.run(args.script_args)
        except SystemExit as exc:
            status = exc.code if type(exc.code) is int else (0 if exc.code is None else 1)
            failure = 'SystemExit' if status else None
        except KeyboardInterrupt:
            status, failure = 130, 'KeyboardInterrupt'
        except Exception as exc:
            status, failure = 1, type(exc).__name__
        records = [{'event': event.payload()} for event in tracer.events]
        review_error = None
        if args.review_config:
            try:
                records = asyncio.run(review(tracer.events, args.review_config))
                if any(r.get('review_status') == 'error' for r in records):
                    review_error = 'One or more batches failed'; status = status or 1
            except Exception as exc: review_error = type(exc).__name__; status = 1
        result = {'schema_version': 1, 'elapsed_ms': tracer.elapsed_ms, 'events': records,
                  'dropped_events': tracer.dropped, 'dropped_count_is_lower_bound': bool(tracer.stopped_reason),
                  'collection_stopped_reason': tracer.stopped_reason, 'collector_errors': tracer.errors,
                  'target_error': failure, 'review_error': review_error, 'limitations': LIMITATIONS}
        json.dump(result, report, indent=2, ensure_ascii=False)
        report.write('\n')
    for record in records:
        meta = record['event']['metadata']
        verdict = record.get('verdict', {}).get('category', 'not_reviewed')
        names = ','.join(meta.get('changed_bindings', meta.get('bindings', {}))) or '-'
        calls = ','.join(c['target'] for c in meta.get('call_candidates', [])) or '-'
        print(f"{verdict:12} #{meta['invocation']} {meta['function']}:{meta['line']} {meta['outcome']} bindings={names} calls={calls}")
    print(f'Report: {args.output}; dropped={tracer.dropped}; errors={tracer.errors}')
    return status


def main(argv=None):
    parser = configure_parser(argparse.ArgumentParser(description=__doc__))
    return execute(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
