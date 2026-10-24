import asyncio
import contextlib
import curses
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mop.cli import main, parser
from mop.core import Event, Verdict, Engine
from mop.variables import VariableTrace, review
from mop.report_ui import ReportState, draw_report, load_report, details
from mop.ui import draw, STYLES
from mop.ui_state import ViewState
from support import FixtureProvider
from test_ui import Screen


def record(category='normal'):
    event = Event('python_variable_step', 'python-runtime', metadata={
        'function': 'clean_text', 'line': 5, 'invocation': 1,
        'call_candidates': [{'target': 'text.upper', 'argument_names': []}],
        'reads_before_line': {'text': {'binding': '1:text:1', 'observed': {'value': 'hello'}}},
        'changed_bindings': {'result': {'observed': {'value': 'HELLO'}}},
        'outcome': 'advanced', 'limitations': 'Scoped observations only.'})
    return {'event': event.payload(), 'verdict': {'category': category}}


class EngineeringPassTests(unittest.TestCase):
    def test_budget_stops_collection_but_not_workload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'job.py'; output = Path(tmp)/'done'
            path.write_text(f"for i in range(10000):\n x=i\nwith open({str(output)!r},'w') as stream:\n stream.write('done')\n")
            trace = VariableTrace(path, 5); trace.run()
            self.assertEqual(output.read_text(), 'done')
            self.assertEqual(len(trace.events), 5)
            self.assertIsNotNone(trace.stopped_reason)
            self.assertEqual(trace.dropped, 1)

    def test_successful_exit_is_not_error_and_private_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'job.py'; path.write_text('raise SystemExit(0)\n')
            output = Path(tmp)/'report.json'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(argv=['variables', '--output', str(output), str(path)]), 0)
            self.assertIsNone(json.loads(output.read_text())['target_error'])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(argv=['variables', '--output', str(output), str(path)]), 2)

    def test_partial_model_failure_keeps_successes(self):
        async def run():
            events = [Event(**record()['event']) for _ in range(9)]
            calls = 0
            async def infer(provider, batch):
                nonlocal calls
                calls += 1
                if calls == 2: raise TimeoutError('do not expose response secrets')
                return [Verdict('normal', 'test', 'fixture') for _ in batch]
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'config.json'
                from mop.classification import DEFAULT_TASK
                path.write_text(json.dumps({'base_url': 'http://127.0.0.1:18936', 'classification': DEFAULT_TASK}))
                with patch('mop.classification.ClassificationProvider.infer_batch', infer):
                    result = await review(events, path)
            self.assertEqual(sum('verdict' in r for r in result), 5)
            self.assertEqual(sum(r['review_status'] == 'error' for r in result), 4)
            self.assertNotIn('response secrets', json.dumps(result))
        asyncio.run(run())

    def test_report_filter_search_and_no_model_calls(self):
        report = {'schema_version': 1, 'events': [record(), record('suspicious')]}
        state = ReportState(mode=2)
        self.assertEqual(len(state.visible(report)), 1)
        state.query = 'missing'; self.assertEqual(state.visible(report), [])
        state.key(ord('='), 0); self.assertEqual(len(state.visible(report)), 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'report.json'; path.write_text(json.dumps(report))
            with patch('mop.classification.ClassificationProvider.infer_batch', side_effect=AssertionError('network')), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(argv=['inspect', '--plain', str(path)]), 0)
            self.assertIn('HELLO', out.getvalue())

    def test_report_sizes_and_terminal_escapes(self):
        item = record(); item['event']['metadata']['function'] = '\x1b[31munsafe'
        report = {'events': [item]}
        for height, width in ((8, 40), (16, 80), (34, 120), (45, 180)):
            screen = Screen(height, width)
            draw_report(screen, report, ReportState(), STYLES)
            self.assertNotIn('\x1b', screen.text())
        screen = Screen(34, 120); draw_report(screen, report, ReportState(), STYLES)
        self.assertIn('BEFORE /', screen.text())
        self.assertIn('AFTER /', screen.text())

    def test_invalid_report_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'bad.json'
            for data in ([], {'schema_version': 1, 'events': [None]}, {'schema_version': 1, 'events': [{'event': {'metadata': {'call_candidates': [None]}}}]}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): load_report(path)

    def test_long_event_details_scroll_in_all_profiles(self):
        engine = Engine(FixtureProvider()); item = record()
        item.update(inference_ms=1, queue_ms=0)
        item['verdict']['reason'] = 'test'
        item['event']['metadata']['tail'] = ['long evidence ' + str(i) for i in range(60)]
        engine.recent.append(item)
        for profile in ('top', 'htop', 'btop'):
            state = ViewState(profile=profile, events=True, overlay='detail')
            screen = Screen(24, 100); draw(screen, [], engine, state, {}, STYLES)
            self.assertGreater(state.overlay_max, 0)
            state.key(curses.KEY_END, engine, [item])
            draw(screen, [], engine, state, {}, STYLES)
            self.assertIn('long evidence 59', screen.text())
            state.key(27, engine, [item]); self.assertEqual(state.overlay_offset, 0)


class DiscoveryRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejected_discovery_retries_without_periodic_review(self):
        from mop.collectors import proc_watch
        from test_ui import row
        process = row(999999)
        engine = Engine(FixtureProvider())
        attempts = []
        def submit(event):
            attempts.append(event)
            return len(attempts) > 1
        with patch('mop.collectors.snapshot', return_value=([process], 0)), patch.object(engine, 'submit', side_effect=submit):
            await proc_watch(engine, .03, .001)
        self.assertEqual(len(attempts), 2)
