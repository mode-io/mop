import asyncio,unittest
from collections import Counter
from mop.tetragon import Adapter,Coalescer
from mop.core import Engine
from mop.cli import parser
from support import FixtureProvider
from test_tetragon import event

class DefaultTests(unittest.TestCase):
 def test_default_enabled_and_can_disable(self):
  self.assertTrue(parser().parse_args(['watch']).tetragon)
  self.assertFalse(parser().parse_args(['watch','--no-tetragon']).tetragon)
 def test_execution_tokens_are_distinct_and_stable(self):
  a=Adapter().parse(event(exec_id='A'*64));b=Adapter().parse(event(exec_id='B'*64))
  self.assertNotEqual(a.metadata['process']['exec_id'],b.metadata['process']['exec_id'])
  self.assertTrue(a.metadata['process']['exec_id'].startswith('exec:'))

class CoalesceTests(unittest.IsolatedAsyncioTestCase):
 async def test_duplicate_counts_and_raw_accounting(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine)
  try:
   for _ in range(4):c.offer(Adapter().parse(event()))
   c.tick(True)
  finally:await engine.close()
  self.assertEqual(len(engine.recent),1)
  r=engine.recent[0]
  self.assertEqual(r['raw_event_count'],4)
  self.assertEqual(r['decision_scope'],'group')
  self.assertEqual(r['event']['metadata']['observations'][0]['count'],4)
  self.assertEqual(engine.stats['raw_events_received'],4)
 async def test_failed_operation_kept_separate(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine)
  try:
   c.offer(Adapter().parse(event()))
   c.offer(Adapter().parse(event(**{'return':{'int_arg':-13}})))
   c.tick(True)
  finally:await engine.close()
  self.assertEqual(len(engine.recent),2)
  self.assertTrue(any(r['event']['metadata']['outcome']=='negative_return' for r in engine.recent))
 async def test_separate_execution_and_thread(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine)
  try:
   c.offer(Adapter().parse(event(exec_id='one')))
   c.offer(Adapter().parse(event(exec_id='two')))
   c.tick(True)
  finally:await engine.close()
  self.assertEqual(len(engine.recent),2)
 async def test_expiry_flushes_while_idle(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine,10)
  try:
   c.offer(Adapter().parse(event()))
   await asyncio.sleep(.02);c.tick()
   self.assertFalse(c.groups)
  finally:await engine.close()

class SourceWindowTests(unittest.IsolatedAsyncioTestCase):
 async def test_replay_source_time_preserves_window_boundaries(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine,250)
  try:
   first=Adapter().parse(event());second=Adapter().parse(event());second.timestamp+=1
   c.offer(first);c.offer(second);c.tick(True)
  finally:await engine.close()
  self.assertEqual(len(engine.recent),2)
 async def test_eight_operation_bound_does_not_drop_events(self):
  engine=await Engine(FixtureProvider()).start();c=Coalescer(engine)
  try:
   for i in range(12):
    raw=event();raw['process_kprobe']['args']=[{'int_arg':i}]
    c.offer(Adapter().parse(raw))
   c.tick(True)
  finally:await engine.close()
  self.assertEqual(engine.stats['raw_events_in_completed_units'],12)
  self.assertEqual(len(engine.recent),2)
