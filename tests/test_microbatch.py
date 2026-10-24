import asyncio, json, unittest
from mop.core import Engine, Event, Verdict
from mop.microbatch import MicroBatchProvider
from test_guard import Server

class Transport:
    name = 'jev-binary'

    def __init__(self, delay=0.005, fail=False):
        self.calls = []
        self.active = 0
        self.peak = 0
        self.delay = delay
        self.fail = fail

    async def infer_batch(self, events):
        self.calls.append(events)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay)
            if self.fail:
                raise ValueError('fixture batch failure')
            return [Verdict('normal' if e.pid % 2 == 0 else 'high_risk', e.id, self.name) for e in events]
        finally:
            self.active -= 1

    def summary(self):
        return {'http_requests': len(self.calls)}

class BatchTests(unittest.IsolatedAsyncioTestCase):

    async def test_one_answer_per_event_and_independent_context(self):
        transport = Transport()
        provider = MicroBatchProvider(transport, 4, 1, 2)
        events = [Event('read', 'fixture', pid=i, context={'task_id': str(i)}) for i in range(16)]
        try:
            answers = await asyncio.gather(*(provider.infer(e) for e in events))
            self.assertEqual([v.reason for v in answers], [e.id for e in events])
            self.assertEqual([v.category for v in answers], ['normal' if i % 2 == 0 else 'high_risk' for i in range(16)])
            self.assertTrue(all((len(batch) <= 4 for batch in transport.calls)))
            self.assertEqual(sum((len(batch) for batch in transport.calls)), 16)
            self.assertEqual(len(transport.calls), 4)
            self.assertTrue(all((e.context['task_id'] == str(e.pid) for b in transport.calls for e in b)))
        finally:
            await provider.aclose()

    async def test_concurrent_batches_are_bounded(self):
        transport = Transport(0.02)
        provider = MicroBatchProvider(transport, 2, 0, 2)
        try:
            await asyncio.gather(*(provider.infer(Event('read', 'fixture')) for _ in range(20)))
            self.assertLessEqual(transport.peak, 2)
        finally:
            await provider.aclose()

    async def test_sparse_event_flushes_without_waiting_for_full_batch(self):
        provider = MicroBatchProvider(Transport(0), 8, 2, 1)
        try:
            answer = await asyncio.wait_for(provider.infer(Event('read', 'fixture')), 0.2)
            self.assertEqual(answer.category, 'normal')
            self.assertEqual(provider.summary()['batch_histogram'], {1: 1})
        finally:
            await provider.aclose()

    async def test_batch_error_fails_every_member(self):
        provider = MicroBatchProvider(Transport(fail=True), 4, 1, 1)
        try:
            results = await asyncio.gather(*(provider.infer(Event('read', 'fixture')) for _ in range(4)), return_exceptions=True)
            self.assertTrue(all((isinstance(x, ValueError) for x in results)))
            self.assertEqual(provider.stats['failed_decisions'], 4)
        finally:
            await provider.aclose()

    async def test_cancelled_caller_does_not_cancel_other_answers(self):
        provider = MicroBatchProvider(Transport(0.02), 4, 1, 1)
        one = asyncio.create_task(provider.infer(Event('read', 'fixture')))
        two = asyncio.create_task(provider.infer(Event('read', 'fixture', pid=1)))
        await asyncio.sleep(0.005)
        one.cancel()
        try:
            self.assertEqual((await two).category, 'high_risk')
            await asyncio.gather(one, return_exceptions=True)
        finally:
            await provider.aclose()

    async def test_close_cancels_pending_and_active(self):
        provider = MicroBatchProvider(Transport(5), 2, 1, 1)
        tasks = [asyncio.create_task(provider.infer(Event('read', 'fixture'))) for _ in range(6)]
        await asyncio.sleep(0.02)
        await provider.aclose()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 0.2)
        self.assertTrue(all((t.done() for t in tasks)))
        self.assertEqual(provider.pending.qsize(), 0)

    async def test_pending_overflow_is_visible(self):
        provider = MicroBatchProvider(Transport(0.02), 1, 0, 1, pending_capacity=1)
        try:
            await asyncio.gather(*(provider.infer(Event('read', 'fixture')) for _ in range(8)), return_exceptions=True)
            self.assertGreater(provider.stats['rejected_pending_full'], 0)
        finally:
            await provider.aclose()

    async def test_engine_keeps_event_scope_and_closes_provider(self):
        provider = MicroBatchProvider(Transport(), 4, 1, 2)
        engine = await Engine(provider, workers=8, capacity=32).start()
        for i in range(12):
            engine.submit(Event('read', 'fixture', pid=i))
        await engine.close()
        self.assertEqual(engine.stats['completed'], 12)
        self.assertTrue(all((r['decision_scope'] == 'event' for r in engine.recent)))
        self.assertTrue(all(('batch_wait_ms' in r['verdict']['timing'] for r in engine.recent)))
        self.assertTrue(provider.closed)

    async def test_provider_snapshots_pending_state(self):
        transport = Transport()
        provider = MicroBatchProvider(transport, 8, 20, 1)
        event = Event('read', 'fixture', context={'task_id': 'original'})
        task = asyncio.create_task(provider.infer(event))
        await asyncio.sleep(0.001)
        event.context['task_id'] = 'changed'
        await task
        await provider.aclose()
        self.assertEqual(transport.calls[0][0].context['task_id'], 'original')

    async def test_engine_does_not_mutate_or_reuse_caller_state(self):
        provider = MicroBatchProvider(Transport(), 4, 1, 1)
        engine = await Engine(provider, context={'task_id': 'operator'}).start()
        event = Event('read', 'fixture', context={'task_id': 'caller'}, metadata={'path': 'original'})
        engine.submit(event)
        event.metadata['path'] = 'changed'
        await engine.close()
        self.assertEqual(event.context['task_id'], 'caller')
        self.assertEqual(engine.recent[0]['event']['metadata']['path'], 'original')

    def test_invalid_bounds_rejected(self):
        for (size, wait) in ((0, 0), (65, 0), (4, -1), (4, float('nan'))):
            with self.assertRaises(ValueError):
                MicroBatchProvider(Transport(), size, wait)
if __name__ == '__main__':
    unittest.main()
