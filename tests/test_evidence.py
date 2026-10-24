import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from mop.evidence import EvidenceCollector, process_identity, tail_file, redact
from mop.core import Event, Engine, Verdict

class EvidenceTests(unittest.TestCase):

    def event(self):
        (start, name, _) = process_identity(os.getpid())
        return Event('process_review', 'proc-review', os.getpid(), os.getpid(), name, metadata={'start_ticks': start})

    def test_runtime_bounded_and_no_environment(self):
        value = EvidenceCollector().collect(self.event())
        self.assertIn('process', value)
        self.assertIn('status', value)
        self.assertNotIn('argv', value)
        self.assertNotIn('environ', value)
        self.assertLessEqual(len(json.dumps(value, ensure_ascii=False).encode()), 6000)

    def test_successive_samples_include_runtime_deltas(self):
        collector = EvidenceCollector()
        event = self.event()
        first = collector.collect(event)
        second = collector.collect(event)
        self.assertNotIn('changes', first)
        self.assertGreaterEqual(second['changes']['elapsed_seconds'], 0)
        self.assertGreaterEqual(second['changes']['cpu_ticks_delta'], 0)
        self.assertIn('io_delta', second['changes'])

    def test_identity_mismatch(self):
        event = self.event()
        event.metadata['start_ticks'] += 1
        with self.assertRaises(ValueError):
            EvidenceCollector().collect(event)

    def test_log_tail_redaction_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'task.log'
            log.write_text('progress\napi_key=fictional-value\nAuthorization: Bearer fictional-value\n')
            result = tail_file(log)
            self.assertEqual(result['status'], 'ok')
            self.assertNotIn('fictional-value', result['tail'])
            secret = root / '.env'
            secret.write_text('do-not-read')
            self.assertEqual(tail_file(secret)['status'], 'skipped_sensitive_path')
            link = root / 'link.log'
            link.symlink_to(log)
            self.assertEqual(tail_file(link)['status'], 'skipped_non_regular')
            fifo = root / 'pipe'
            os.mkfifo(fifo)
            self.assertEqual(tail_file(fifo)['status'], 'skipped_non_regular')
            self.assertEqual(tail_file(log, roots=[root / 'other'])['status'], 'skipped_outside_output_roots')

    def test_tail_drops_partial_first_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'task.log'
            path.write_text('prefix-secret-value\nlast line\n')
            result = tail_file(path, limit=20)
            self.assertNotIn('secret', result['tail'])
            self.assertIn('last line', result['tail'])
            self.assertTrue(result['truncated'])

    def test_regular_stdout_tail_has_independent_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stdout.log'
            with path.open('w+') as writer:
                writer.write('hello\n')
                writer.flush()
                position = writer.tell()
                result = tail_file('/proc/self/fd/' + str(writer.fileno()), roots=[Path(directory)], via_fd=True)
                self.assertIn('hello', result['tail'])
                self.assertEqual(writer.tell(), position)

class EvidenceEngineTests(unittest.IsolatedAsyncioTestCase):

    async def test_missing_evidence_does_not_call_model(self):

        class Collector:

            def collect(self, event):
                raise ValueError('identity changed')

        class Provider:
            name = 'test'

            async def infer(self, event):
                raise AssertionError('must not be called')
        engine = Engine(Provider())
        engine.evidence_collector = Collector()
        await engine.start()
        engine.submit(Event('process_review', 'proc-review'))
        await engine.close()
        self.assertEqual(engine.recent[-1]['verdict']['category'], 'unknown')
        self.assertNotIn('runtime_evidence', engine.recent[-1]['event']['metadata'])

    async def test_collected_evidence_reaches_model_and_audit_record(self):

        class Collector:

            def collect(self, event):
                return {'marker': 'collected'}

        class Provider:
            name = 'test'

            async def infer(self, event):
                assert event.metadata['runtime_evidence']['marker'] == 'collected'
                return Verdict('suspicious', 'ok', self.name)
        engine = Engine(Provider())
        engine.evidence_collector = Collector()
        await engine.start()
        engine.submit(Event('process_review', 'proc-review'))
        await engine.close()
        self.assertEqual(engine.stats['evidence_collected'], 1)
        self.assertIn('runtime_evidence', engine.recent[-1]['event']['metadata'])

    async def test_periodic_review_revisits_existing_process(self):
        from unittest.mock import patch
        from mop.collectors import proc_watch
        from support import FixtureProvider
        from test_ui import row
        engine = await Engine(FixtureProvider(0)).start()
        engine.review_interval = 0.02
        with patch('mop.collectors.snapshot', return_value=([row(999999)], 0)):
            await proc_watch(engine, 0.07, 0.01)
        await engine.close()
        self.assertGreaterEqual(engine.stats['completed'], 2)
        self.assertIn('process_review', [r['event']['operation'] for r in engine.recent])
