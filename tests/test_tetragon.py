import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from mop.tetragon import Adapter, consume, open_regular
from mop.core import Engine
from support import FixtureProvider


def event(kind='process_kprobe',pid=987654,exec_id='exec-one',**detail):
    return {kind:{'process':{'pid':pid,'tid':pid,'uid':os.getuid(),'exec_id':exec_id,'binary':'/usr/bin/python3'},
                  'function_name':'security_file_permission','args':[{'file_arg':{'path':'/tmp/report'}}],**detail},
            'node_name':'local','time':'2026-10-18T12:00:00Z'}


class AdapterTests(unittest.TestCase):
    def test_rich_event_and_no_pid_only_advice(self):
        item=Adapter().parse(event(**{'return':{'int_arg':-13}}))
        self.assertEqual(item.metadata['outcome'],'negative_return')
        self.assertEqual(item.metadata['observation']['args'][0]['file_arg']['path'],'/tmp/report')
        self.assertNotIn('start_ticks',item.metadata)
        self.assertEqual(item.context,{})

    def test_real_nanosecond_timestamp_on_python310(self):
        raw=event();raw['time']='2026-10-18T14:37:28.662169441Z'
        parsed=Adapter().parse(raw)
        self.assertEqual(parsed.metadata['source_timestamp'],raw['time'])
        self.assertGreater(parsed.timestamp,0)

    def test_missing_return_is_not_success(self):
        self.assertEqual(Adapter().parse(event()).metadata['outcome'],'not_reported')

    def test_uid_filter_and_missing_identity(self):
        self.assertIsNone(Adapter(os.getuid()+1).parse(event()))
        raw=event();del raw['process_kprobe']['process']['uid']
        with self.assertRaises(ValueError):Adapter().parse(raw)

    def test_history_uses_exec_identity_not_pid(self):
        adapter=Adapter()
        adapter.parse(event())
        self.assertEqual(len(adapter.parse(event()).metadata['recent_same_execution']),1)
        self.assertEqual(adapter.parse(event(exec_id='reused-pid')).metadata['recent_same_execution'],[])

    def test_secrets_redacted_and_arguments_optional(self):
        raw=event();raw['process_kprobe']['process']['arguments']='--password=example-secret'
        raw['process_kprobe']['args']=[{'string_arg':'{"password":"example-secret"}'}]
        value=Adapter(include_args=False).parse(raw)
        self.assertNotIn('arguments',value.metadata['process'])
        self.assertNotIn('example-secret',json.dumps(value.payload()))

    def test_symlink_and_nonregular_input_refused(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'data';target.write_text('')
            link=Path(d)/'link';link.symlink_to(target)
            with self.assertRaises(OSError):open_regular(link)
            fifo=Path(d)/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):open_regular(fifo)


class StreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_group_mode_keeps_kernel_arguments_and_identity(self):
        engine=await Engine(FixtureProvider(),level='process').start()
        try:
            engine.submit(Adapter().parse(event()))
            engine.submit(Adapter().parse(event(exec_id='different-exec')))
        finally:await engine.close()
        self.assertEqual(len(engine.recent),2)
        self.assertTrue(all(r['event']['source']=='tetragon' for r in engine.recent))

    async def test_replay_partial_and_oversize_counted(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events'
            path.write_text('bad json\n'+'x'*70000+'\n'+json.dumps(event()))
            engine=await Engine(FixtureProvider()).start()
            try:await consume(engine,path,uid=os.getuid())
            finally:await engine.close()
            self.assertEqual(engine.stats['tetragon_invalid'],1)
            self.assertEqual(engine.stats['tetragon_oversized'],1)
            self.assertEqual(engine.stats['completed'],1)

    async def test_follow_partial_line_and_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events';path.write_text('')
            engine=await Engine(FixtureProvider()).start()
            task=asyncio.create_task(consume(engine,path,follow=True,duration=.6))
            try:
                await asyncio.sleep(.05)
                raw=json.dumps(event())
                with path.open('a') as f:f.write(raw[:30])
                await asyncio.sleep(.15)
                self.assertEqual(engine.stats['tetragon_events'],0)
                with path.open('a') as f:f.write(raw[30:]+'\n')
                await asyncio.sleep(.15)
                path.rename(Path(d)/'old');path.write_text(json.dumps(event(exec_id='new'))+'\n')
                await task
            finally:
                task.cancel();await asyncio.gather(task,return_exceptions=True);await engine.close()
            self.assertEqual(engine.stats['completed'],2)
            self.assertEqual(engine.stats['tetragon_source_resets'],1)


class WatchIntegrationTests(unittest.TestCase):
    def test_existing_watch_consumes_kernel_events_without_ui_changes(self):
        import contextlib
        import io
        import threading
        import time
        from unittest.mock import patch, AsyncMock
        from mop.cli import main
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source.jsonl';source.write_text('')
            audit=Path(d)/'audit.jsonl'
            def append():
                time.sleep(.15)
                with source.open('a') as stream:stream.write(json.dumps(event())+'\n')
            writer=threading.Thread(target=append);writer.start()
            try:
                with patch('mop.ambient.follow',new=AsyncMock()), patch('mop.cli.provider_from',return_value=FixtureProvider()), patch('mop.collectors.snapshot',return_value=([],0)), contextlib.redirect_stdout(io.StringIO()):
                    result=main(argv=['watch','--plain','--duration','.5','--interval','.05','--evidence','none',
                                      '--tetragon-log',str(source),'--log',str(audit)])
            finally:writer.join()
            self.assertEqual(result,0)
            records=[json.loads(line) for line in audit.read_text().splitlines()]
            self.assertEqual(len(records),1)
            self.assertEqual(records[0]['event']['source'],'tetragon')
