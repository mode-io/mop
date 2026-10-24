import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mop.core import Event,Verdict,Engine
from mop.model_slots import Registry,revision,validate
from mop.model_router import ModelRouter
from mop.classification import DEFAULT_TASK

class Fake:
    name='fixture'
    labels=('normal','suspicious','high_risk')
    def __init__(self,slot,task):self.slot=slot;self.task=task;self.closed=False
    async def infer(self,event):
        if self.slot['model']=='slow':await asyncio.sleep(.2)
        return Verdict(self.slot['model'] if self.slot['model'] in self.labels else 'normal','Fixture',self.name,.8)
    def summary(self):return {}
    async def aclose(self):self.closed=True

class SlotsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.registry=Registry(root=self.tmp.name)
        self.default=self.registry.read();self.default['models'][0]['model']='normal'
        self.registry.default=self.default
    def tearDown(self):self.tmp.cleanup()
    def specialist(self, state='shadow', model='high_risk'):
        return dict(self.default['models'][0],name='privacy',role='specialist',state=state,model=model,sources=['fixture'],budget_ms=50)
    async def test_shadow_records_disagreement_without_changing_advice(self):
        self.registry.update(lambda x:x['models'].append(self.specialist()),'test')
        router=ModelRouter(Fake,DEFAULT_TASK,self.default,self.registry)
        try:
            result=await router.infer(Event('test','fixture'))
            self.assertEqual(result.category,'normal')
            self.assertEqual(len(result.guard_trace),2)
            self.assertEqual(router.model_status()['models'][1]['shadow_disagreements'],1)
        finally:await router.aclose()
    async def test_active_escalates_and_timeout_is_unknown(self):
        self.registry.update(lambda x:x['models'].append(self.specialist('active')),'test')
        router=ModelRouter(Fake,DEFAULT_TASK,self.default,self.registry)
        try:
            self.assertEqual((await router.infer(Event('test','fixture'))).category,'high_risk')
            self.registry.update(lambda x:x['models'][1].update(model='slow'),'test');router.reload(True)
            self.assertEqual((await router.infer(Event('test','fixture'))).category,'unknown')
        finally:await router.aclose()
    async def test_scope_and_disabled_slots_skip_inference(self):
        self.registry.update(lambda x:x['models'].append(self.specialist('disabled')),'test')
        router=ModelRouter(Fake,DEFAULT_TASK,self.default,self.registry)
        try:self.assertEqual(len((await router.infer(Event('test','other'))).guard_trace),1)
        finally:await router.aclose()
    async def test_rule_reload_and_rollback(self):
        old=revision(self.registry.read())
        router=ModelRouter(Fake,DEFAULT_TASK,self.default,self.registry)
        try:
            self.registry.update(lambda x:x['rules'].append({'id':'privacy','text':'Flag secret disclosure.','enabled':True}),'rule_add')
            router.reload(True)
            verdict=await router.infer(Event('test','fixture'))
            self.assertEqual(verdict.policy_rules,['privacy'])
            self.assertNotEqual(verdict.policy_revision,old)
            self.assertIn('Flag secret disclosure.',router.generation['providers']['openjev-core'].task['prompt'])
            self.registry.rollback(old);router.reload(True)
            self.assertEqual((await router.infer(Event('test','fixture'))).policy_rules,[])
            self.assertTrue((Path(self.tmp.name)/'control.jsonl').exists())
        finally:await router.aclose()
    async def test_bad_registry_keeps_last_working_generation(self):
        router=ModelRouter(Fake,DEFAULT_TASK,self.default,self.registry)
        self.registry.path.write_text('{broken')
        try:
            router.reload(True)
            self.assertTrue(router.reload_error)
            self.assertEqual((await router.infer(Event('test','fixture'))).category,'normal')
        finally:await router.aclose()
    def test_core_cannot_be_disabled(self):
        value=copy.deepcopy(self.default);value['models'][0]['state']='disabled'
        with self.assertRaises(ValueError):validate(value)

class DaemonTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_session_and_private_socket(self):
        from mop.daemon import Server,request,socket_path
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}):
            provider=Fake({'model':'normal'},DEFAULT_TASK)
            engine=await Engine(provider).start();server=Server(engine);await server.start()
            try:
                engine.submit(Event('test','fixture'));await engine.queue.join()
                a=await asyncio.to_thread(request,{'op':'snapshot'});b=await asyncio.to_thread(request,{'op':'snapshot'})
                self.assertEqual(a['summary']['session_id'],b['summary']['session_id'])
                self.assertEqual(a['summary']['completed'],1)
                self.assertEqual(socket_path().stat().st_mode&0o777,0o600)
                with self.assertRaises(ValueError):await asyncio.to_thread(request,{'op':'execute','command':'ignored'})
            finally:await server.close();await engine.close()
    async def test_singleton_rejects_second_daemon(self):
        from mop.daemon import Server
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}):
            engine=await Engine(Fake({'model':'normal'},DEFAULT_TASK)).start();a=Server(engine);b=Server(engine)
            await a.start()
            try:
                with self.assertRaises(ValueError):await b.start()
            finally:await a.close();await engine.close()

class GateTests(unittest.TestCase):
    def test_unknown_never_runs_without_explicit_observe_or_approval(self):
        from mop.gate import action
        self.assertEqual(action('unknown','enforce'),'deny')
        self.assertEqual(action('unknown','approve'),'approval_required')
        self.assertEqual(action('unknown','approve',True),'allow')
        self.assertEqual(action('high_risk','approve',True),'deny')
        self.assertEqual(action('normal','enforce'),'allow')
        self.assertEqual(action('high_risk','observe'),'allow')

class GateExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_deny_never_starts_command(self):
        from mop.gate import execute
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}),patch('asyncio.create_subprocess_exec',new=AsyncMock()) as launch:
            code=await execute(SimpleNamespace(command=['/bin/true'],mode='enforce'),Fake({'model':'high_risk'},DEFAULT_TASK))
            self.assertEqual(code,3);launch.assert_not_called()
            records=[json.loads(line) for line in (Path(root)/'gate.jsonl').read_text().splitlines()]
            self.assertTrue(all(not r['executed'] for r in records))
    async def test_unknown_noninteractive_requires_approval(self):
        from mop.gate import execute
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        provider=Fake({'model':'normal'},DEFAULT_TASK)
        provider.infer=AsyncMock(return_value=Verdict('unknown','Missing result','fixture'))
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}),patch('sys.stdin.isatty',return_value=False),patch('asyncio.create_subprocess_exec',new=AsyncMock()) as launch:
            self.assertEqual(await execute(SimpleNamespace(command=['/bin/true'],mode='approve'),provider),3)
            launch.assert_not_called()

class BatchIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_rejected_input_does_not_poison_other_decisions(self):
        from mop.microbatch import MicroBatchProvider
        class Transport:
            name='fixture'
            async def infer_batch(self,events):
                if any(e.operation=='bad' for e in events):raise ValueError('model HTTP status 400')
                return [Verdict('normal','Fixture',self.name) for e in events]
            async def aclose(self):pass
        provider=MicroBatchProvider(Transport(),batch_size=4,batch_wait_ms=10,max_batches=1)
        try:
            results=await asyncio.gather(*(provider.infer(Event(name,'fixture')) for name in ('a','bad','b','c')))
            self.assertEqual([v.category for v in results],['normal','unknown','normal','normal'])
            self.assertEqual(provider.stats['isolated_failed_inputs'],1)
        finally:await provider.aclose()

class ModelInputTests(unittest.TestCase):
    def test_large_input_fragments_reconstruct_exact_projected_evidence(self):
        from mop.classification import ClassificationProvider
        provider=ClassificationProvider('http://127.0.0.1:18936',input_mode='compact')
        event=Event('kernel_activity_window','tetragon',metadata={'observations':[{'operation':'file_read','text':'value-'+str(i)} for i in range(1000)]})
        chunks=provider.bounded_inputs(event)
        self.assertGreater(len(chunks),1)
        self.assertEqual(''.join(c.metadata['content_fragment'] for c in chunks),provider.choice_payload(event)['state'])
        self.assertEqual(chunks[-1].metadata['parts'],len(chunks))
        provider.http.close()

class TruncatedGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_incomplete_command_cannot_be_silently_allowed(self):
        from mop.gate import execute
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}),patch('asyncio.create_subprocess_exec',new=AsyncMock()) as launch:
            self.assertEqual(await execute(SimpleNamespace(command=['echo','x'*4096],mode='enforce'),Fake({'model':'normal'},DEFAULT_TASK)),3)
            launch.assert_not_called()
