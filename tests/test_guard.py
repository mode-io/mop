import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from mop.collectors import parse_strace, trace_command
from mop.core import Engine, Event, Verdict
from mop.classification import ClassificationProvider
from support import FixtureProvider
from mop.proc import snapshot
from mop.ui import safe

class Server:

    def __init__(self, response=None, status=200, delay=0):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                outer.requests.append((self.path, body))
                time.sleep(delay)
                data = json.dumps(response).encode()
                self.send_response(status)
                self.end_headers()
                try:
                    self.wfile.write(data)
                except BrokenPipeError:
                    pass

            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

class PipelineTests(unittest.IsolatedAsyncioTestCase):

    async def test_every_accepted_event_gets_own_inference(self):
        engine = await Engine(FixtureProvider(1), workers=2, capacity=10).start()
        for _ in range(10):
            engine.submit(Event('read', 'test'))
        await engine.close()
        self.assertEqual(engine.stats['accepted'], 10)
        self.assertEqual(engine.stats['inference_attempts'], 10)
        self.assertEqual(engine.stats['completed'], 10)
        self.assertTrue(all((not r['enforced'] for r in engine.recent)))

    async def test_overload_is_counted_not_silently_allowed(self):
        engine = await Engine(FixtureProvider(5), workers=1, capacity=2).start()
        for _ in range(10):
            engine.submit(Event('read', 'test'))
        await engine.close()
        self.assertEqual(engine.stats['dropped_queue_full'], 8)
        self.assertEqual(engine.stats['completed'], 2)

    async def test_error_is_unknown_and_not_response_body(self):

        class Broken:
            name = 'broken'

            async def infer(self, event):
                raise RuntimeError('SECRET_TOKEN')
        engine = await Engine(Broken()).start()
        engine.submit(Event('read', 'test'))
        await engine.close()
        self.assertEqual(engine.stats['unknown'], 1)
        self.assertNotIn('SECRET_TOKEN', json.dumps(list(engine.recent)))

    async def test_timeout_is_unknown(self):
        with Server({}, delay=0.15) as server:
            engine = await Engine(ClassificationProvider(server.url, timeout=0.02)).start()
            engine.submit(Event('read', 'test'))
            await engine.close()
            self.assertEqual(engine.stats['unknown'], 1)

    async def test_log_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'events.jsonl'
            engine = await Engine(FixtureProvider(0), log=p).start()
            engine.submit(Event('open', 'test'))
            await engine.close()
            self.assertEqual(p.stat().st_mode & 511, 384)
            self.assertFalse(json.loads(p.read_text())['enforced'])

    async def test_real_strace_observes_command_without_arguments(self):
        import shutil
        if not shutil.which('strace'):
            self.skipTest('strace unavailable')
        privileged = os.environ.get('MOP_TEST_SUDO_TRACE') == '1'
        ptrace_scope = Path('/proc/sys/kernel/yama/ptrace_scope')
        if ptrace_scope.exists() and int(ptrace_scope.read_text()) >= 2 and (not privileged):
            self.skipTest('host restricts ptrace; explicit sudo trace test required')
        engine = await Engine(FixtureProvider(0), capacity=4096).start()
        result = await trace_command(engine, ['/bin/echo', 'PRIVATE_MARKER'], 'all', 5, privileged)
        await engine.close()
        self.assertEqual(result, 0)
        self.assertGreater(engine.stats['completed'], 0)
        self.assertNotIn('PRIVATE_MARKER', json.dumps(list(engine.recent)))

    async def test_event_tui_quit_cancels_collector_cleanly(self):
        from unittest.mock import patch
        from mop.ui import event_monitor

        class Screen:

            def nodelay(self, value):
                pass

            def getch(self):
                return ord('q')
        engine = await Engine(FixtureProvider(0)).start()
        task = asyncio.create_task(asyncio.sleep(60))
        with patch('curses.curs_set'):
            result = await event_monitor(Screen(), engine, task)
        await engine.close()
        self.assertEqual(result, 130)
        self.assertTrue(task.cancelled())

    async def test_trace_command_keeps_caller_uid(self):
        if os.environ.get('MOP_TEST_SUDO_TRACE') != '1':
            self.skipTest('explicit privileged integration test only')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'uid.txt'
            import sys
            command = [sys.executable, '-c', 'import os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(str(os.getuid()))', str(path)]
            engine = await Engine(FixtureProvider(0), capacity=4096).start()
            result = await trace_command(engine, command, 'security', 5, True)
            await engine.close()
            self.assertEqual(result, 0)
            self.assertEqual(int(path.read_text()), os.getuid())

    async def test_trace_deadline_terminates_own_command_group(self):
        if os.environ.get('MOP_TEST_SUDO_TRACE') != '1':
            self.skipTest('explicit privileged integration test only')
        engine = await Engine(FixtureProvider(0), capacity=4096).start()
        start = time.monotonic()
        result = await trace_command(engine, ['/bin/sleep', '20'], 'security', 0.1, True)
        await engine.close()
        self.assertEqual(result, 124)
        self.assertLess(time.monotonic() - start, 3)

class ValidationTests(unittest.TestCase):

    def test_remote_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            ClassificationProvider('https://example.com', model='x')
        with self.assertRaises(ValueError):
            ClassificationProvider('http://example.com', model='x', allow_remote=True)
        ClassificationProvider('https://example.com/v1', model='x', allow_remote=True)

    def test_url_credentials_rejected(self):
        with self.assertRaises(ValueError):
            ClassificationProvider('http://token@localhost:8000')

    def test_event_schema(self):
        with self.assertRaises(ValueError):
            Event.from_dict({'operation': 'read', 'source': 'test', 'pid': 'bad'})
        with self.assertRaises(ValueError):
            Verdict('normal', 'bad', 'test', float('nan'))

    def test_proc_current_process(self):
        (rows, _) = snapshot()
        self.assertTrue(any((row['pid'] == os.getpid() for row in rows)))

    def test_parser_handles_thread_prefix_and_unfinished(self):
        event = parse_strace('1234 1720000000.123456 openat(0x1, 0x2 <unfinished ...>')
        self.assertEqual(event.tid, 1234)
        self.assertEqual(event.pid, 0)
        self.assertEqual(event.operation, 'openat')
        self.assertIsNone(parse_strace('1234 1720000000.123457 <... openat resumed>) = 0'))
        self.assertIsNone(parse_strace('strace: warning'))

    def test_terminal_escape_sanitized(self):
        self.assertNotIn('\x1b', safe('\x1b[2J'))
if __name__ == '__main__':
    unittest.main()
