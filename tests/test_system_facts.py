import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from mop.audit import AuditLog
from mop.collectors import parse_strace,trace_command
from mop.core import Engine,Event
from mop.evidence import EvidenceCollector,process_identity,redact
from mop.system_facts import argument_facts,sockets_for
from mop.trace_evidence import TraceDecoder
from support import FixtureProvider

class FactsTests(unittest.TestCase):
    def test_arguments_preserve_late_flags_and_redact_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'cmdline'
            args=['python']+['arg%d'%i for i in range(30)]+['--port','8795','--port','18936','--api-key','SECRET_WITH_SPACES','--password=ANOTHER SECRET','--max-num-batched-tokens','8192']
            path.write_bytes(b'\0'.join(x.encode() for x in args)+b'\0')
            facts=argument_facts(path,redact)
            self.assertFalse(facts['truncated'])
            self.assertEqual(facts['values'].count('--port'),2)
            self.assertIn('18936',facts['values'])
            self.assertIn('8192',facts['values'])
            self.assertNotIn('SECRET',json.dumps(facts))

    def test_socket_matching_does_not_include_other_process_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'net').mkdir()
            (root/'net/tcp').write_text('header\n0: 0100007F:49F8 00000000:0000 0A 0:0 0:0 0 1001 0 1234\n1: 0100007F:2328 00000000:0000 0A 0:0 0:0 0 1001 0 9999\n')
            rows,coverage=sockets_for(root,{'1234'})
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['local'],{'address':'127.0.0.1','port':18936,'loopback':True})
            self.assertEqual(rows[0]['state'],'LISTEN')
            self.assertIn('tcp6',coverage)

    def test_descriptor_changes_are_observed_without_inventing_actions(self):
        collector=EvidenceCollector()
        start,name,_=process_identity(os.getpid())
        event=Event('process_review','proc-review',os.getpid(),os.getpid(),name,metadata={'start_ticks':start})
        with tempfile.TemporaryDirectory() as directory, patch.object(collector.facts,'gpu',return_value={'status':'test fixture'}):
            collector.collect(event)
            path=Path(directory)/'newly-open.txt'
            with path.open('w'):
                value=collector.collect(event)
            # Check the collector state too: projection may omit a detail under its budget.
            current=collector.previous[(event.pid,event.tid,start)]
            self.assertIn(str(path),current['files'])
            self.assertIn('Snapshot differences',value['changes']['scope'])

    def test_live_process_facts_and_full_evidence_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'stdout.log';data=root/'data.txt'
            code='import socket,sys,time; f=open(sys.argv[1],"w+"); f.write("fixture"); f.flush(); s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); print(s.getsockname()[1],flush=True); print("api_key=FAKE_LOG_VALUE",flush=True); time.sleep(10)'
            with output.open('wb') as stream:
                child=subprocess.Popen([sys.executable,'-u','-c',code,str(data)],stdout=stream,stderr=stream,env={**os.environ,'OMP_NUM_THREADS':'7','PRIVATE_API_KEY':'SECRET_ENV_VALUE'})
            try:
                for _ in range(100):
                    if output.read_text().count('\n')>=2:break
                    time.sleep(.01)
                port=int(output.read_text().splitlines()[0]);start,name,_=process_identity(child.pid)
                collector=EvidenceCollector(auto_output=True,evidence_log=AuditLog(root/'full.jsonl'))
                with patch.object(collector.facts,'gpu',return_value={'status':'test fixture'}):
                    result=collector.collect(Event('process_review','proc-review',child.pid,child.pid,name,metadata={'start_ticks':start}))
                collector.close()
                full=json.loads((root/'full.jsonl').read_text())['evidence']
                self.assertTrue(any(r.get('local',{}).get('port')==port for r in full['system']['connections']))
                self.assertTrue(any(r['target']==str(data) and r['access_mode']=='read_write' for r in full['system']['open_files']))
                self.assertTrue(any(r['pid']==os.getpid() for r in full['system']['ancestry']))
                self.assertNotIn('FAKE_LOG_VALUE',json.dumps(result))
                self.assertNotIn('SECRET_ENV_VALUE',json.dumps(full))
                self.assertEqual(full['system']['runtime_environment']['values']['OMP_NUM_THREADS'],'7')
                self.assertEqual(result['evidence_sufficiency']['status'],'limited')
                self.assertLessEqual(len(json.dumps(result,ensure_ascii=False).encode()),6000)
                self.assertNotIn('user_intent',full)
            finally:child.terminate();child.wait(timeout=3)

    def test_json_log_and_connection_string_redaction(self):
        from mop.evidence import tail_file
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'stdout.log'
            path.write_text('{"password":"SECRET WITH SPACES"}\npostgres://user:DB_SECRET@127.0.0.1/db\n')
            text=tail_file(path)['tail']
            self.assertNotIn('SECRET',text)
            self.assertIn('[REDACTED]',text)

class DecodeTests(unittest.TestCase):
    def test_thread_evidence_uses_thread_start_identity(self):
        from mop.security_view import advice_for,advice_index,indexed_advice
        row={'pid':10,'tid':11,'start_ticks':22}
        record={'event':{'pid':10,'tid':11,'metadata':{'start_ticks':20,'thread_start_ticks':22}},'verdict':{'category':'normal'}}
        self.assertEqual(advice_for(row,[record]),'normal')
        self.assertEqual(indexed_advice(row,advice_index([record])),'normal')


    def test_completed_operation_includes_actual_arguments_and_result(self):
        event=parse_strace('123 1720000000.123456 unlink("/tmp/fixture") = 0',True)
        self.assertIn('/tmp/fixture',event.metadata['arguments'])
        self.assertEqual(event.metadata['outcome'],'completed')
        failed=parse_strace('123 1720000000.123456 openat(AT_FDCWD, "/tmp/no", O_RDONLY) = -1 ENOENT (No such file)',True)
        self.assertEqual(failed.metadata['outcome'],'failed')
        self.assertEqual(failed.metadata['errno'],'ENOENT')

    def test_argument_text_cannot_forge_a_successful_return_value(self):
        event=parse_strace('123 1720000000.123456 unlink("/tmp/evil) = 0") = -1 EACCES (Permission denied)',True)
        self.assertEqual(event.metadata['result'],'-1')
        self.assertEqual(event.metadata['outcome'],'failed')

    def test_exec_secret_and_resumed_calls(self):
        event=parse_strace('123 1720000000.123456 execve("/bin/app", ["app", "--api-key", "SECRET"], 0x0 /* 2 vars */) = 0',True)
        self.assertNotIn('SECRET',event.metadata['arguments'])
        decoder=TraceDecoder(parse_strace)
        self.assertIsNone(decoder.feed('123 1720000000.123456 connect(3, {sa_family=AF_INET, sin_port=htons(18936)}, 16 <unfinished ...>'))
        event=decoder.feed('123 1720000000.223456 <... connect resumed>) = 0')
        self.assertEqual(event.operation,'connect')
        self.assertEqual(event.metadata['outcome'],'completed')
        self.assertIn('18936',event.metadata['arguments'])
        self.assertEqual(event.metadata['completion_timestamp'],1720000000.223456)

class TraceIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_decoded_trace_and_safe_attachment(self):
        if os.environ.get('MOP_TEST_SUDO_TRACE')!='1':self.skipTest('explicit privileged integration only')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'observed.txt'
            engine=await Engine(FixtureProvider(),capacity=4096).start()
            code='import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text("fixture"); p.unlink()'
            try:result=await trace_command(engine,[sys.executable,'-c',code,str(path),'--api-key','SECRET_ARG'],'security',5,True,True)
            finally:await engine.close()
            self.assertEqual(result,0)
            rows=list(engine.recent)
            self.assertTrue(any(r['event']['operation']=='unlink' and str(path) in r['event']['metadata']['arguments'] and r['event']['metadata']['outcome']=='completed' for r in rows))
            self.assertNotIn('SECRET_ARG',json.dumps(rows))
            target=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'])
            attached=await Engine(FixtureProvider(),capacity=4096).start()
            try:
                await trace_command(attached,[],'security',.2,True,True,target.pid)
                self.assertIsNone(target.poll())
            finally:
                await attached.close();target.terminate();target.wait(timeout=3)
