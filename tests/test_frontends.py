import asyncio
import contextlib
import curses
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from mop.cli import main, parser
from mop.config import apply_config
from mop.core import Engine, Event
from support import FixtureProvider
from mop.frontends import spark, page_rows
from mop.security_view import banner, status, advice_for
from mop.ui import draw, STYLES
from mop.ui_state import ViewState
from test_ui import Screen, row

class FrontendTests(unittest.TestCase):

    def test_three_profiles_have_distinct_layouts(self):
        outputs = {}
        for profile in ('top', 'htop', 'btop'):
            screen = Screen(34, 120)
            draw(screen, [row(10)], Engine(FixtureProvider()), ViewState(profile=profile), {}, STYLES)
            outputs[profile] = screen.text()
        self.assertIn('%Cpu(s)', outputs['top'])
        self.assertIn('F10Quit', outputs['htop'])
        self.assertIn('GUARD / model advice', outputs['btop'])
        self.assertEqual(len(set(outputs.values())), 3)

    def test_every_profile_displays_only_classification_categories(self):
        for profile in ('top','htop','btop'):
            screen=Screen(34,150);engine=Engine(FixtureProvider())
            engine.category_counts.update(normal=3,suspicious=2,high_risk=1)
            engine.stats.update(unknown=2,raw_dropped_queue_full=4)
            draw(screen,[],engine,ViewState(profile=profile),{},STYLES)
            text=screen.text().upper()
            for expected in ('NORMAL','SUSPICIOUS','HIGH_RISK','UNASSESSED'):self.assertIn(expected,text)
            self.assertNotIn('MOCK',text)
            self.assertNotIn('REVIEW',text)

    def test_render_does_not_change_engine_policy_or_counters(self):
        engine = Engine(FixtureProvider())
        before = dict(engine.stats)
        for profile in ('top', 'htop', 'btop'):
            draw(Screen(34, 120), [row(10)], engine, ViewState(profile=profile), {}, STYLES)
        self.assertEqual(dict(engine.stats), before)
        self.assertEqual(engine.granularity.level, 'event')

    def test_all_profiles_handle_resizing(self):
        for profile in ('top', 'htop', 'btop'):
            for (height, width) in ((8, 40), (16, 60), (24, 80), (34, 120)):
                screen = Screen(height, width)
                draw(screen, [row(10)], Engine(FixtureProvider()), ViewState(profile=profile), {}, STYLES)

    def test_dashboard_small_terminal_has_compact_fallback(self):
        screen = Screen(20, 70)
        draw(screen, [], Engine(FixtureProvider()), ViewState(profile='btop'), {}, STYLES)
        self.assertIn('B-MOP compact', screen.text())

    def test_dashboard_menu_and_view_shortcuts(self):
        state = ViewState(profile='btop')
        state.key(ord('m'), None, [])
        self.assertEqual(state.overlay, 'models')
        state.key(27, None, [])
        state.key(ord('2'), None, [])
        self.assertTrue(state.events)
        state.key(ord('1'), None, [])
        self.assertFalse(state.events)

    def test_dashboard_escape_opens_menu_not_quit(self):
        state = ViewState(profile='btop')
        self.assertFalse(state.key(27, None, []))
        self.assertEqual(state.overlay, 'setup')

    def test_history_is_bounded(self):
        state = ViewState()
        state.history['cpu'].extend(range(1000))
        self.assertEqual(len(state.history['cpu']), 90)

    def test_spark_bounds_and_warmup(self):
        self.assertIn(spark([None, 0, 50, 100], 4, 100), (' .:#', ' ▁▄█'))
        self.assertEqual(len(spark(range(100), 10)), 10)

    def test_model_advice_requires_process_lifetime_match(self):
        process = row(10)
        event = Event('read', 'fixture', pid=10, tid=10, metadata={'start_ticks': 1})
        record = {'event': event.payload(), 'verdict': {'category': 'suspicious'}}
        self.assertEqual(advice_for(process, [record]), 'suspicious')
        process['start_ticks'] = 2
        self.assertEqual(advice_for(process, [record]), '-')

    def test_no_identity_does_not_become_safe_badge(self):
        event = Event('read', 'fixture', pid=10, tid=10)
        record = {'event': event.payload(), 'verdict': {'category': 'normal'}}
        self.assertEqual(advice_for(row(10), [record]), '-')

    def test_group_advice_not_converted_to_allow(self):
        event = Event('operation_batch', 'fixture', pid=10, metadata={'start_ticks': 1})
        record = {'event': event.payload(), 'verdict': {'category': 'normal'}, 'decision_scope': 'group'}
        self.assertEqual(advice_for(row(10), [record]), 'group')

    def test_raw_unassessed_and_waiting_are_distinct(self):
        result = status({'raw_events_received': 20, 'raw_events_in_completed_units': 10, 'raw_dropped_queue_full': 3, 'raw_abandoned_shutdown': 2})
        self.assertEqual(result['unassessed'], 5)
        self.assertEqual(result['waiting'], 5)

    def test_no_alerts_is_not_a_safe_claim(self):
        text=banner({'categories':{'normal':0,'suspicious':0,'high_risk':0}})
        self.assertIn('CLASSIFICATION',text)
        self.assertNotIn('safe',text.lower())

    def test_profile_aware_page_size(self):
        self.assertEqual(page_rows('top', 24), 14)
        self.assertEqual(page_rows('btop', 24), 5)

    def test_ui_config_and_explicit_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ui.json'
            path.write_text('{"ui":"btop"}')
            argv = ['watch', '--config', str(path)]
            args = apply_config(parser('htop').parse_args(argv), argv)
            self.assertEqual(args.ui, 'btop')
            argv += ['--ui', 'top']
            args = apply_config(parser('htop').parse_args(argv), argv)
            self.assertEqual(args.ui, 'top')

    def test_watch_defaults_to_until_quit(self):
        argv = ['watch']
        args = apply_config(parser().parse_args(argv), argv)
        self.assertIsNone(args.duration)

    def test_aggregated_identity_can_show_group_advice(self):
        event = Event('operation_batch', 'mop-aggregation', pid=10, metadata={'aggregation': {'effective_level': 'process', 'group': ['proc-poll', '10', '1']}})
        record = {'event': event.payload(), 'verdict': {'category': 'normal'}, 'decision_scope': 'group'}
        self.assertEqual(advice_for(row(10), [record]), 'group')
        newer = row(10)
        newer['start_ticks'] = 2
        self.assertEqual(advice_for(newer, [record]), '-')
        record['event']['tid'] = 11
        self.assertEqual(advice_for(row(10), [record]), '-')

    def test_invalid_ui_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ui.json'
            path.write_text('{"ui":"invalid"}')
            argv = ['watch', '--config', str(path)]
            with self.assertRaises(ValueError):
                apply_config(parser().parse_args(argv), argv)

class CommandTests(unittest.TestCase):

    def test_default_entry_selects_watch_and_profile(self):
        from unittest.mock import patch
        for profile in ('top','htop','btop'):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream), patch('mop.cli.provider_from',return_value=FixtureProvider()):
                result=main(profile,['--plain','--duration','0.01','--evidence','none'])
            self.assertEqual(result,0)
            self.assertIn('"ui": "'+profile+'"',stream.getvalue())

    def test_three_shell_commands(self):
        root = Path(__file__).resolve().parents[1]
        for (command, brand) in (('mop', 'MOP'), ('hmop', 'H-MOP'), ('bmop', 'B-MOP')):
            result = subprocess.run([str(root / 'scripts' / command), '--version'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout.startswith(brand + ' '))

    def test_all_profiles_support_event_view(self):
        engine = Engine(FixtureProvider())
        event = Event('synthetic-operation', 'fixture', pid=10, tid=10)
        engine.recent.append({'event': event.payload(), 'verdict': {'category': 'suspicious', 'reason': 'fixture'}, 'inference_ms': 50, 'queue_ms': 0, 'raw_event_count': 1})
        for profile in ('top', 'htop', 'btop'):
            screen = Screen(34, 120)
            draw(screen, [row(10)], engine, ViewState(profile=profile, events=True), {}, STYLES)
            self.assertIn('synthetic-operation', screen.text())
if __name__ == '__main__':
    unittest.main()
