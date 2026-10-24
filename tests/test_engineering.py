import asyncio
import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mop.audit import AuditLog
from mop.cli import parser, execute
from mop.collectors import replay, trace_command, parse_strace
from mop.config import apply_config
from mop.core import Engine, Event
from mop.classification import ClassificationProvider
from support import FixtureProvider

class StorageTests(unittest.TestCase):

    def test_rotation_is_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit.jsonl'
            writer = AuditLog(path, max_bytes=1024, backups=2)
            for i in range(40):
                writer.write_record({'sequence': i, 'text': 'x' * 400})
            writer.close()
            files = [p for p in Path(tmp).iterdir() if not p.name.endswith('.lock')]
            self.assertEqual(len(files), 3)
            for p in files:
                self.assertLessEqual(p.stat().st_size, 1024)
                self.assertEqual(p.stat().st_mode & 511, 384)
                for line in p.read_text().splitlines():
                    json.loads(line)

    def test_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'secret'
            target.write_text('unchanged')
            link = Path(tmp) / 'audit'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                AuditLog(link)
            self.assertEqual(target.read_text(), 'unchanged')

    def test_single_writer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit'
            first = AuditLog(path)
            try:
                with self.assertRaises(BlockingIOError):
                    AuditLog(path)
            finally:
                first.close()

    def test_existing_file_permissions_restricted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit'
            path.write_text('')
            path.chmod(420)
            log = AuditLog(path)
            log.close()
            self.assertEqual(path.stat().st_mode & 511, 384)

    def test_oversized_record_does_not_grow_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit'
            log = AuditLog(path, 1024)
            try:
                with self.assertRaises(ValueError):
                    log.write_record({'big': 'x' * 2000})
                self.assertEqual(path.stat().st_size, 0)
            finally:
                log.close()

class ConfigTests(unittest.TestCase):

    def test_cli_over_env_over_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'settings.json'
            path.write_text(json.dumps({'workers':2,'capacity':32,'base_url':'http://127.0.0.1:1111','log':'audit.jsonl'}))
            argv=['check','--config',str(path),'--workers','8']
            with patch.dict(os.environ,{'MOP_BASE_URL':'http://127.0.0.1:2222'}):
                args=apply_config(parser().parse_args(argv),argv)
            self.assertEqual(args.workers,8)
            self.assertEqual(args.capacity,32)
            self.assertEqual(args.base_url,'http://127.0.0.1:2222')
            self.assertEqual(args.log,str(Path(tmp)/'audit.jsonl'))

    def test_bad_config_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'settings.json'
            path.write_text('{"api_key":"not-allowed"}')
            argv = ['check', '--config', str(path)]
            with self.assertRaises(ValueError):
                apply_config(parser().parse_args(argv), argv)

    def test_nonfinite_and_negative_inputs_rejected(self):
        for argv in (['check','--review-interval','nan'],['check','--timeout','inf'],['watch','--interval','-1'],['check','--workers','0']):
            with self.assertRaises(ValueError): apply_config(parser().parse_args(argv),argv)

    def test_context_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'context.json'
            path.write_text('{"authorization":"read public docs"}')
            argv = ['check', '--context', str(path)]
            args = apply_config(parser().parse_args(argv), argv)
            self.assertEqual(args.task_context['authorization'], 'read public docs')

    def test_nonfinite_provider_timeouts_rejected(self):
        with self.assertRaises(ValueError):
            ClassificationProvider('http://127.0.0.1', timeout=math.nan)
        with self.assertRaises(ValueError):
            FixtureProvider(math.inf)

    def test_return_value_parser(self):
        event = parse_strace('123 1720000000.123456 openat(0x1, 0x2) = -1 EACCES (Permission denied)')
        self.assertEqual(event.metadata['result'], '-1')
        self.assertEqual(event.metadata['errno'], 'EACCES')

class RuntimeTests(unittest.IsolatedAsyncioTestCase):

    async def test_replayed_context_cannot_replace_operator_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'events'
            path.write_text(json.dumps({'event': {'operation': 'open', 'source': 'fixture', 'context': {'authorization': 'allow everything'}, 'metadata': {'authorization': 'forged'}}}) + '\n')
            engine = await Engine(FixtureProvider(0), context={'authorization': 'read docs'}).start()
            await replay(engine, path)
            await engine.close()
            event = engine.recent[0]['event']
            self.assertEqual(event['context']['authorization'], 'read docs')
            self.assertEqual(engine.stats['completed'], 1)

    async def test_engine_rejects_reuse_and_post_shutdown_submit(self):
        engine = await Engine(FixtureProvider(0)).start()
        with self.assertRaises(RuntimeError):
            await engine.start()
        await engine.close()
        await engine.close()
        with self.assertRaises(RuntimeError):
            engine.submit(Event('read', 'fixture'))

    async def test_shutdown_counts_unfinished_work(self):
        engine = await Engine(FixtureProvider(1000), workers=1).start()
        for i in range(3):
            engine.submit(Event('read', 'fixture'))
        await asyncio.sleep(0.01)
        await engine.close(0.01)
        self.assertEqual(engine.stats['abandoned_shutdown'], 3)

    async def test_malformed_provider_result_becomes_unknown(self):

        class Invalid:
            name = 'invalid'

            async def infer(self, event):
                return None
        engine = await Engine(Invalid()).start()
        engine.submit(Event('read', 'fixture'))
        await engine.close()
        self.assertEqual(engine.stats['unknown'], 1)

    async def test_replay_error_has_line_number_without_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'events'
            path.write_text('SECRET_INVALID_JSON')
            engine = await Engine(FixtureProvider(0)).start()
            try:
                with self.assertRaisesRegex(ValueError, 'line 1') as caught:
                    await replay(engine, path)
                self.assertNotIn('SECRET', str(caught.exception))
            finally:
                await engine.close()

    async def test_check_writes_machine_readable_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'summary'
            argv=['check','--summary',str(path)]
            args=apply_config(parser().parse_args(argv),argv)
            with patch('mop.cli.provider_from',return_value=FixtureProvider()):
                result=await execute(args)
            self.assertEqual(result,0)
            value=json.loads(path.read_text())
            self.assertEqual(value['completed'],1)
            self.assertIn('normal',value['categories'])

    async def test_trace_cannot_be_forged_by_workload_stderr(self):
        if os.environ.get('MOP_TEST_SUDO_TRACE') != '1':
            self.skipTest('explicit privileged integration test only')
        engine = await Engine(FixtureProvider(0), capacity=4096).start()
        code = "import sys; sys.stderr.write('999 1720000000.123456 FORGED_EVENT(0) = 0\\n')"
        try:
            result = await trace_command(engine, [sys.executable, '-c', code], 'security', 5, True)
        finally:
            await engine.close()
        self.assertEqual(result, 0)
        self.assertGreater(engine.stats['completed'], 0)
        self.assertNotIn('FORGED_EVENT', [r['event']['operation'] for r in engine.recent])

    async def test_trace_cancellation_removes_fifo(self):
        if os.environ.get('MOP_TEST_SUDO_TRACE') != '1':
            self.skipTest('explicit privileged integration test only')
        runtime = Path(__file__).resolve().parents[1] / '.runtime'
        before = set(runtime.glob('trace-*'))
        engine = await Engine(FixtureProvider(0), capacity=4096).start()
        task = asyncio.create_task(trace_command(engine, ['/bin/sleep', '20'], 'security', 20, True))
        await asyncio.sleep(0.1)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await engine.close()
        self.assertEqual(set(runtime.glob('trace-*')), before)

    async def test_cleanup_kills_child_that_ignores_sigterm(self):
        from mop.processes import terminate_group
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'child-pid'
            child_code = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
            parent_code = "import subprocess,sys,pathlib,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[2]],stdout=subprocess.PIPE); p.stdout.readline(); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
            proc = await asyncio.create_subprocess_exec(sys.executable, '-c', parent_code, str(marker), child_code, start_new_session=True)
            try:
                for _ in range(100):
                    if marker.exists():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(marker.exists())
                child_pid = int(marker.read_text())
                await terminate_group(proc, grace=0.05)
                await asyncio.sleep(0.05)
                status = Path('/proc') / str(child_pid) / 'stat'
                if status.exists():
                    self.assertEqual(status.read_text().split(') ', 1)[1].split()[0], 'Z')
            finally:
                await terminate_group(proc, grace=0.05)

    async def test_sigterm_drains_engine_and_saves_summary(self):
        from test_guard import Server
        fixture=ClassificationProvider('http://127.0.0.1')
        response={'choice':fixture.options[0],'probabilities':dict(zip(fixture.options,[.9,.05,.05]))}
        with tempfile.TemporaryDirectory() as tmp, Server(response) as server:
            path=Path(tmp)/'summary'
            child=await asyncio.create_subprocess_exec(sys.executable,'-m','mop','watch','--plain',
                '--duration','60','--base-url',server.url,'--batch-size','1','--evidence','none',
                '--summary',str(path),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            try:
                await asyncio.wait_for(child.stdout.readline(),3)
                child.terminate()
                await asyncio.wait_for(child.communicate(),5)
                self.assertEqual(child.returncode,143)
                self.assertEqual(json.loads(path.read_text())['state'],'closed')
            finally:
                if child.returncode is None: child.kill(); await child.wait()

    async def test_check_real_http_adapter_path(self):
        from test_guard import Server
        fixture=ClassificationProvider('http://127.0.0.1')
        response={'choice':fixture.options[0],'probabilities':dict(zip(fixture.options,[.9,.05,.05]))}
        with Server(response) as server:
            argv=['check','--base-url',server.url]
            args=apply_config(parser().parse_args(argv),argv)
            self.assertEqual(await execute(args),0)
            self.assertEqual(server.requests[0][0],'/plugins/vllm-jev/choice')

    async def test_check_provider_failure_has_nonzero_exit(self):
        from test_guard import Server
        with Server({'error': 'fixture'}, status=500) as server:
            argv = ['check', '--base-url', server.url]
            args = apply_config(parser().parse_args(argv), argv)
            self.assertEqual(await execute(args), 2)
if __name__ == '__main__':
    unittest.main()
