import importlib.util
import unittest
from pathlib import Path
from mop.core import Engine, Event, Verdict
from mop.security_view import advice_for, advice_index, indexed_advice
from support import FixtureProvider
from test_ui import row

class RetentionTests(unittest.IsolatedAsyncioTestCase):

    async def test_expired_and_inflight_results_do_not_repopulate_live_cache(self):
        engine = await Engine(FixtureProvider(0), history_limit=100).start()
        engine.retain_visible_identities([row(1)])
        engine.submit(Event('task_discovered', 'test', 1, 1, metadata={'start_ticks': 1}))
        await engine.queue.join()
        self.assertEqual(len(engine.latest_advice), 1)
        engine.retain_visible_identities([row(2)])
        self.assertFalse(engine.latest_advice)
        engine.submit(Event('task_discovered', 'test', 1, 1, metadata={'start_ticks': 1}))
        await engine.close()
        self.assertFalse(engine.latest_advice)
        self.assertEqual(len(engine.recent), 2)

    async def test_pid_reuse_does_not_keep_old_generation(self):
        engine = await Engine(FixtureProvider(0)).start()
        engine.retain_visible_identities([row(1)])
        engine.submit(Event('task_discovered', 'test', 1, 1, metadata={'start_ticks': 1}))
        await engine.queue.join()
        engine.retain_visible_identities([dict(row(1), start_ticks=2)])
        self.assertFalse(engine.latest_advice)
        await engine.close()

class IndexTests(unittest.TestCase):

    def test_index_preserves_identity_and_latest_wildcard_semantics(self):
        records = []
        for (pid, tid, generation, decision) in [(1, 1, 1, 'normal'), (1, 0, 1, 'suspicious'), (1, 2, 1, 'high_risk'), (2, 2, 1, 'normal')]:
            records.append({'event': {'pid': pid, 'tid': tid, 'metadata': {'start_ticks': generation}}, 'verdict': {'category': decision}})
        indexed = advice_index(records)
        for r in [row(1), row(1, tid=2), row(2), dict(row(1), start_ticks=2), row(3)]:
            self.assertEqual(indexed_advice(r, indexed), advice_for(r, records))

    def test_index_preserves_group_semantics(self):
        record = {'event': {'pid': 1, 'tid': 1, 'source': 'mop-aggregation', 'metadata': {'aggregation': {'effective_level': 'process', 'group': [1, 1]}}}, 'decision_scope': 'group', 'verdict': {'category': 'suspicious'}}
        self.assertEqual(indexed_advice(row(1), advice_index([record])), 'group')

    def test_sizing_respects_memory_and_reports_shortfall(self):
        spec = importlib.util.spec_from_file_location('sizing', Path(__file__).resolve().parents[1] / 'scripts/size-retention.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.size_history(418 / 72)
        self.assertEqual(result['recommended_history_limit'], 8192)
        self.assertTrue(result['target_with_headroom_met'])
        result = module.size_history(100)
        self.assertFalse(result['target_with_headroom_met'])
        self.assertLessEqual(result['estimated_history_mib'], 128)
