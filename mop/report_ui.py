"""Offline variable-report explorer. Viewing never executes tasks or calls a model."""
import curses
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import sys
import textwrap

from .ui import fit, safe, initialize, STYLES


COLORS = {'normal': 'green', 'suspicious': 'yellow', 'high_risk': 'red', 'error': 'red', 'unknown': 'yellow'}


def load_report(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024: raise ValueError('report exceeds 32 MiB')
    report = json.loads(raw)
    if not isinstance(report, dict) or report.get('schema_version') != 1 or not isinstance(report.get('events'), list):
        raise ValueError('expected a version 1 variable report')
    if len(report['events']) > 4096: raise ValueError('report exceeds 4096 events')
    for record in report['events']:
        if (not isinstance(record, dict) or not isinstance(record.get('event'), dict)
                or not isinstance(record['event'].get('metadata'), dict)
                or not isinstance(record.get('verdict', {}), dict)):
            raise ValueError('invalid report event')
        metadata = record['event']['metadata']
        if any(not isinstance(metadata.get(key, {}), dict) for key in ('reads_before_line', 'changed_bindings', 'bindings')):
            raise ValueError('invalid variable bindings')
        calls = metadata.get('call_candidates', [])
        if not isinstance(calls, list) or any(not isinstance(c, dict) for c in calls):
            raise ValueError('invalid call candidates')
    return report


def category(record):
    value = record.get('verdict', {}).get('category')
    return str(value) if value else ('error' if record.get('review_status') == 'error' else 'recorded')


def details(record, raw=False):
    if raw:
        return ['EXACT REQUEST / JSON', *json.dumps(record.get('request', {'note': 'No inference requested.'}), indent=2, ensure_ascii=False).splitlines()]
    meta = record['event']['metadata']
    lines = [f"{meta.get('function', '?')} : line {meta.get('line', '?')}",
             f"Invocation #{meta.get('invocation', '?')} | parent #{meta.get('parent_invocation', '-')}",
             'Outcome: ' + str(meta.get('outcome', '?'))]
    if meta.get('exception_type'): lines.append('Exception: ' + str(meta['exception_type']))
    if record.get('review_error'): lines.append('Review error: ' + str(record['review_error']))
    scores = record.get('verdict', {}).get('probabilities', {})
    if isinstance(scores, dict) and scores:
        lines.extend(['', 'MODEL SCORES (not calibrated)', ' | '.join(
            str(key) + ': ' + (f'{value:.1%}' if type(value) in (int, float) else '?')
            for key, value in scores.items())])
    for heading, key in [('BEFORE / referenced bindings', 'reads_before_line'), ('AFTER / changed bindings', 'changed_bindings'), ('ENTRY / arguments and locals', 'bindings')]:
        values = meta.get(key, {})
        if not values: continue
        lines.extend(['', heading])
        for name, value in values.items():
            lines.append(str(name))
            if isinstance(value, dict):
                lines.append('  version: ' + str(value.get('binding', '?')))
                observed = value.get('observed', {})
                if isinstance(observed, dict) and 'value' in observed:
                    lines.append('  ' + str(observed.get('type', 'value')) + (' | length ' + str(observed['length']) if 'length' in observed else ''))
                    lines.append('  ' + json.dumps(observed['value'], ensure_ascii=False))
                else:
                    lines.append('  ' + json.dumps(observed, ensure_ascii=False))
    calls = meta.get('call_candidates', [])
    if calls:
        lines.extend(['', 'USE / call candidates (not proven dataflow)'])
        for call in calls: lines.append(str(call.get('target', '?')) + ' | ' + json.dumps(call.get('argument_names', [])))
    if 'return_value' in meta: lines.extend(['', 'RETURN', json.dumps(meta['return_value'], ensure_ascii=False)])
    if meta.get('no_longer_observed'): lines.append('No longer observed: ' + json.dumps(meta['no_longer_observed']))
    lines.extend(['', 'COVERAGE', str(meta.get('limitations', 'Not specified'))])
    return lines


@dataclass
class ReportState:
    index: int = 0
    offset: int = 0
    max_offset: int = 0
    mode: int = 0
    query: str = ''
    editing: bool = False
    raw: bool = False

    def visible(self, report):
        rows = report['events']
        if self.mode == 1: rows = [r for r in rows if 'verdict' in r or category(r) == 'error']
        if self.mode == 2: rows = [r for r in rows if category(r) in ('suspicious', 'high_risk', 'error', 'unknown')]
        if self.query:
            rows = [r for r in rows if self.query.casefold() in json.dumps(r['event'], ensure_ascii=False).casefold()]
        self.index = max(0, min(self.index, len(rows) - 1))
        return rows

    def key(self, key, count, page=10):
        if self.editing:
            if key in (27, 10, 13): self.editing = False
            elif key in (127, 8, curses.KEY_BACKSPACE): self.query = self.query[:-1]
            elif 32 <= key <= 126: self.query = (self.query + chr(key))[:128]
            self.index = self.offset = 0
            return False
        if key in (ord('q'), 27, curses.KEY_F10): return True
        if key in (curses.KEY_DOWN, ord('j'), curses.KEY_UP, ord('k'), curses.KEY_HOME, curses.KEY_END):
            self.index = (0 if key == curses.KEY_HOME else count - 1 if key == curses.KEY_END else self.index + (1 if key in (curses.KEY_DOWN, ord('j')) else -1))
            self.index = max(0, min(self.index, count - 1)); self.offset = 0
        elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE):
            self.offset = max(0, min(self.max_offset, self.offset + (page if key == curses.KEY_NPAGE else -page)))
        elif key in (ord('f'), 9): self.mode = (self.mode + 1) % 3; self.index = self.offset = 0
        elif key == ord('/'): self.editing = True
        elif key == ord('='): self.mode = 0; self.query = ''; self.index = self.offset = 0
        elif key == ord('p'): self.raw = not self.raw; self.offset = 0
        return False


def draw_report(screen, report, state, palette=None):
    palette = palette or dict.fromkeys(STYLES, 0)
    height, width = screen.getmaxyx()
    screen.erase()
    def put(y, x, text, style='normal', limit=None):
        if not (0 <= y < height and 0 <= x < width): return
        text = fit(text, min(width - x - 1, limit if limit is not None else width))
        try: screen.addnstr(y, x, text, len(text), palette[style])
        except curses.error: pass
    if width < 80 or height < 16:
        put(0, 0, 'MOP report: resize to 80x16; q exits', 'title'); screen.refresh(); return
    rows = state.visible(report)
    counts = Counter(category(r) for r in report['events'])
    put(0, 1, 'MOP / VARIABLE EXPLORER                              OFFLINE REPORT', 'title')
    put(1, 1, ' | '.join(f'{key} {counts[key]}' for key in ('normal', 'suspicious', 'high_risk', 'error', 'recorded')), 'yellow')
    gaps = report.get('collection_stopped_reason') or ('Event drops recorded' if report.get('dropped_events') else 'No reported event drops')
    put(2, 1, str(gaps) + ' | collector errors ' + str(report.get('collector_errors', 0)), 'red' if report.get('dropped_events') or report.get('collector_errors') else 'muted')
    put(3, 1, 'Filter: ' + ('all', 'reviewed', 'alerts')[state.mode] + ' | Search: ' + (state.query or '-') + ('_' if state.editing else ''), 'title')
    if report.get('target_error') or report.get('review_error'):
        put(4, 1, 'Run error: ' + str(report.get('target_error') or '-') + ' | Review error: ' + str(report.get('review_error') or '-'), 'red')
    left = min(54, max(30, width // 3))
    page = height - 8
    put(5, 1, ' CATEGORY     FUNCTION : LINE', 'header', left - 2)
    put(5, left + 1, ' EXACT REQUEST' if state.raw else ' VARIABLE VALUES / USE / RESULT', 'header')
    start = max(0, state.index - page + 1)
    for i, row in enumerate(rows[start:start + page]):
        meta = row['event']['metadata']; label = category(row)
        text = f"{label:12} {meta.get('function', '?')}:{meta.get('line', '?')}"
        style = 'selected' if start + i == state.index else COLORS.get(label, 'muted')
        put(6 + i, 1, text.ljust(left - 2), style, left - 2)
    for y in range(5, height - 2): put(y, left - 1, '|', 'muted')
    content = details(rows[state.index], state.raw) if rows else ['No matching observations', 'Press = to clear filters.']
    wrapped = [part for line in content for part in (textwrap.wrap(safe(line), max(10, width - left - 3), replace_whitespace=False) or [''])]
    state.max_offset = max(0, len(wrapped) - page)
    state.offset = min(state.offset, state.max_offset)
    for i, line in enumerate(wrapped[state.offset:state.offset + page]):
        style = 'title' if line.startswith(('BEFORE /', 'AFTER /', 'USE /', 'ENTRY /', 'COVERAGE', 'RETURN', 'MODEL SCORES')) else 'normal'
        put(6 + i, left + 1, line, style)
    put(height - 2, 1, f'{state.index + 1 if rows else 0}/{len(rows)} observations | detail {state.offset + 1}/{len(wrapped)} | recorded != normal', 'muted')
    put(height - 1, 1, 'Up/Down select  PgUp/PgDn detail  f filter  / search  p request  = reset  q quit', 'key')
    screen.refresh()


def inspect_report(path, plain=False):
    report = load_report(path)
    if plain:
        for record in report['events']:
            print(safe('[' + category(record) + ']'))
            for line in details(record): print(safe(line))
            print()
        return 0
    if not sys.stdout.isatty(): raise ValueError('use --plain when stdout is not a terminal')
    def run(screen):
        palette = initialize(screen)
        screen.timeout(200)
        state = ReportState()
        while True:
            draw_report(screen, report, state, palette)
            if state.key(screen.getch(), len(state.visible(report)), max(1, screen.getmaxyx()[0] - 8)): return 0
    return curses.wrapper(run)
