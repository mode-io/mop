import asyncio,json,os,tempfile,unittest
from pathlib import Path
from mop.core import Engine,Verdict
from mop.tetragon import Adapter,consume
from test_tetragon import event
class Slow:
 name='test-only'
 async def infer(self,event):
  await asyncio.sleep(.002)
  return Verdict('normal','Test only',self.name)
class PressureTests(unittest.IsolatedAsyncioTestCase):
 async def test_backpressure_preserves_burst_and_eof_flush(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'input'
   path.write_text('\n'.join(json.dumps(event(exec_id=str(i))) for i in range(300))+'\n')
   engine=await Engine(Slow(),workers=2,capacity=4).start()
   try:await consume(engine,path,window_ms=250)
   finally:await engine.close()
   self.assertEqual(engine.stats['raw_events_in_completed_units'],300)
   self.assertEqual(engine.stats['raw_dropped_queue_full'],0)
   self.assertGreater(engine.stats['tetragon_backpressure_waits'],0)
 async def test_upstream_loss_notification_is_not_silently_filtered(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'input';path.write_text(json.dumps({'rate_limit_info':{'number_of_dropped_process_events':'12'}})+'\n')
   engine=await Engine(Slow()).start()
   try:await consume(engine,path)
   finally:await engine.close()
   self.assertEqual(engine.stats['tetragon_export_lost'],12)
   self.assertEqual(engine.stats['kernel_events_lost'],0)
   self.assertEqual(engine.stats['log_errors'],1)
   self.assertEqual(engine.stats['completed'],0)
 async def test_cancellation_does_not_hang_with_full_queue(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'input';path.write_text('\n'.join(json.dumps(event(exec_id=str(i))) for i in range(300)))
   engine=await Engine(Slow(),workers=1,capacity=1).start()
   task=asyncio.create_task(consume(engine,path,follow=True,window_ms=250))
   await asyncio.sleep(.03);task.cancel()
   await asyncio.wait_for(asyncio.gather(task,return_exceptions=True),2)
   await engine.close()
 def test_ancestor_and_stacks_survive_projection(self):
  raw=event();body=raw['process_kprobe']
  body['ancestors']=[{'pid':1,'uid':0,'exec_id':'parent','binary':'/sbin/init'}]
  body['kernel_stack_trace']=[{'symbol':'do_sys_open','offset':'0'}]
  body['user_stack_trace']=[{'symbol':'main','module':'/synthetic/tool'}]
  parsed=Adapter().parse(raw)
  self.assertEqual(parsed.metadata['ancestors'][0]['binary'],'/sbin/init')
  self.assertEqual(parsed.metadata['observation']['kernel_stack_trace'][0]['symbol'],'do_sys_open')
 def test_uprobe_symbol_and_loader_path_preserved(self):
  for kind in ('process_uprobe','process_loader','process_usdt','process_lsm'):
   raw=event(kind=kind,path='/synthetic/lib.so',symbol='transform',buildid='test',tags=['audit'])
   parsed=Adapter().parse(raw)
   self.assertEqual(parsed.metadata['observation']['path'],'/synthetic/lib.so')
   self.assertEqual(parsed.metadata['observation']['symbol'],'transform')
