import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from mop.core import Engine, Event
from support import FixtureProvider
from mop.cli import parser
from mop.config import apply_config

def events():
    return [Event('read' if i % 2 else 'write', 'fixture', pid=100 + i % 2, tid=1000 + i % 4) for i in range(24)]

class GranularityTests(unittest.IsolatedAsyncioTestCase):

    async def test_six_levels_have_expected_inference_units(self):
        expected = {'event': 24, 'thread': 4, 'process': 2, 'window': 1, 'task': 1, 'host': 1}
        for (level, count) in expected.items():
            with self.subTest(level=level):
                engine = await Engine(FixtureProvider(0), level=level, window_ms=10000, context={'window_id': 'declared-window', 'task_id': 'task'}).start()
                for event in events():
                    engine.submit(event)
                await engine.close()
                self.assertEqual(engine.stats['inference_attempts'], count)
                self.assertEqual(engine.stats['raw_events_received'], 24)
                self.assertEqual(engine.stats['raw_events_in_completed_units'], 24)
                self.assertEqual(engine.stats['events_buffered'], 0)
                self.assertEqual(engine.stats['raw_dropped_queue_full'], 0)

    async def test_time_window_flushes_without_shutdown(self):
        engine = await Engine(FixtureProvider(0), level='process', window_ms=20).start()
        engine.submit(Event('read', 'fixture', pid=10, tid=11))
        try:
            for _ in range(100):
                if engine.stats['completed']:
                    break
                await asyncio.sleep(0.005)
            self.assertEqual(engine.stats['completed'], 1)
            self.assertEqual(engine.recent[0]['event']['metadata']['aggregation']['flush_reason'], 'time_window')
        finally:
            await engine.close()

    async def test_max_events_flush(self):
        engine = await Engine(FixtureProvider(0), level='process', window_ms=10000, max_events=3).start()
        for _ in range(7):
            engine.submit(Event('read', 'fixture', pid=10, tid=11))
        await engine.close()
        self.assertEqual(engine.stats['completed'], 3)
        self.assertEqual(sum((r['raw_event_count'] for r in engine.recent)), 7)

    async def test_live_switch_flushes_old_groups(self):
        engine = await Engine(FixtureProvider(0), level='thread', window_ms=10000).start()
        for _ in range(3):
            engine.submit(Event('read', 'fixture', pid=10, tid=11))
        engine.set_level('event')
        engine.submit(Event('write', 'fixture', pid=10, tid=11))
        await engine.close()
        self.assertEqual(engine.stats['completed'], 2)
        batch = next((r for r in engine.recent if r['raw_event_count'] == 3))
        self.assertEqual(batch['event']['metadata']['aggregation']['requested_level'], 'thread')
        self.assertEqual(batch['event']['metadata']['aggregation']['flush_reason'], 'level_change')

    async def test_group_capacity_is_bounded_and_accounted(self):
        engine = await Engine(FixtureProvider(0), level='thread', window_ms=10000, max_groups=2).start()
        for i in range(8):
            engine.submit(Event('read', 'fixture', tid=100 + i))
            self.assertLessEqual(len(engine.granularity.groups), 2)
        await engine.close()
        self.assertEqual(engine.stats['group_capacity_flushes'], 6)
        self.assertEqual(engine.stats['raw_events_in_completed_units'], 8)

    async def test_overflow_counts_raw_operations_not_just_batches(self):
        engine = await Engine(FixtureProvider(0), level='process', window_ms=10000, max_events=2, capacity=1, workers=1).start()
        for _ in range(6):
            engine.submit(Event('read', 'fixture', pid=10, tid=11))
        await engine.close()
        self.assertEqual(engine.stats['dropped_queue_full'], 2)
        self.assertEqual(engine.stats['raw_dropped_queue_full'], 4)
        self.assertEqual(engine.stats['raw_events_in_completed_units'], 2)

    async def test_missing_process_identity_falls_back_visibly(self):
        engine = await Engine(FixtureProvider(0), level='process', window_ms=10000).start()
        engine.submit(Event('read', 'fixture', tid=11))
        engine.submit(Event('read', 'fixture', tid=12))
        await engine.close()
        self.assertEqual(engine.stats['identity_fallback_to_thread'], 2)
        self.assertEqual(engine.stats['completed'], 2)
        self.assertTrue(all((r['event']['metadata']['aggregation']['effective_level'] == 'thread' for r in engine.recent)))

    async def test_missing_all_identity_does_not_merge_unrelated_events(self):
        engine = await Engine(FixtureProvider(0), level='thread', window_ms=10000).start()
        for _ in range(3):
            engine.submit(Event('read', 'fixture'))
        await engine.close()
        self.assertEqual(engine.stats['completed'], 3)
        self.assertEqual(engine.stats['identity_fallback_to_event'], 3)

    async def test_samples_are_bounded_and_omission_is_visible(self):
        engine = await Engine(FixtureProvider(0), level='host', window_ms=10000).start()
        for event in events():
            engine.submit(event)
        await engine.close()
        batch = engine.recent[0]['event']['metadata']['aggregation']
        self.assertEqual(len(batch['sampled_events']), 8)
        self.assertEqual(batch['omitted_sample_count'], 16)
        self.assertEqual(sum(batch['operation_counts'].values()), 24)

    async def test_proposed_operations_bypass_batching(self):
        engine = await Engine(FixtureProvider(0), level='host', window_ms=10000).start()
        engine.submit(Event('exec', 'fixture', phase='proposed'))
        self.assertEqual(engine.stats['accepted'], 1)
        self.assertEqual(len(engine.granularity.groups), 0)
        await engine.close()

    async def test_invalid_live_switch_preserves_pending_groups(self):
        engine = await Engine(FixtureProvider(0), level='thread', window_ms=10000).start()
        engine.submit(Event('read', 'fixture', tid=11))
        with self.assertRaises(ValueError):
            engine.set_level('window')
        self.assertEqual(len(engine.granularity.groups), 1)
        await engine.close()

    async def test_end_to_end_includes_aggregation_dwell(self):
        engine = await Engine(FixtureProvider(0), level='host', window_ms=10000).start()
        engine.submit(Event('read', 'fixture'))
        await asyncio.sleep(0.02)
        await engine.close()
        record = engine.recent[0]
        self.assertGreaterEqual(record['aggregation_ms'], 15)
        self.assertGreaterEqual(record['end_to_end_ms'], record['aggregation_ms'])

    async def test_live_window_switch_flushes_pending_data(self):
        engine = await Engine(FixtureProvider(0), level='host', window_ms=10000).start()
        engine.submit(Event('read', 'fixture'))
        engine.set_window_ms(100)
        await engine.close()
        self.assertEqual(engine.stats['completed'], 1)
        self.assertEqual(engine.recent[0]['event']['metadata']['aggregation']['flush_reason'], 'window_change')
        self.assertEqual(engine.summary()['granularity']['window_ms'], 100)

    async def test_live_identity_resolver_maps_current_thread(self):
        import os
        from mop.collectors import resolve_trace_identity
        event = Event('read', 'fixture', tid=os.getpid())
        self.assertTrue(resolve_trace_identity(event))
        self.assertEqual(event.pid, os.getpid())
        self.assertIn('start_ticks', event.metadata)

    async def test_generation_keeps_reused_pid_separate(self):
        engine = await Engine(FixtureProvider(0), level='process', window_ms=10000).start()
        for generation in (1, 2):
            engine.submit(Event('read', 'fixture', pid=10, metadata={'start_ticks': generation}))
        await engine.close()
        self.assertEqual(engine.stats['completed'], 2)

class GranularityConfigTests(unittest.TestCase):

    def test_window_and_task_require_context(self):
        for level in ('window', 'task'):
            argv = ['watch', '--plain', '--level', level]
            with self.assertRaises(ValueError):
                apply_config(parser().parse_args(argv), argv)

    def test_explicit_window_context_enables_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'context'
            path.write_text('{"window_id":"terminal-A"}')
            argv = ['watch', '--plain', '--level', 'window', '--context', str(path)]
            args = apply_config(parser().parse_args(argv), argv)
            self.assertEqual(args.task_context['window_id'], 'terminal-A')

    def test_single_assessment_cannot_use_group_verdict(self):
        argv = ['check', '--level', 'process']
        with self.assertRaises(ValueError):
            apply_config(parser().parse_args(argv), argv)

    def test_context_free_levels_exclude_window_and_task(self):
        engine = Engine(FixtureProvider(0))
        self.assertEqual(engine.granularity.available_levels(), ['event', 'thread', 'process', 'host'])
if __name__ == '__main__':
    unittest.main()
