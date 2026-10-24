import json,tempfile,unittest
from pathlib import Path
from mop.core import Engine,Event
from mop.microbatch import MicroBatchProvider
from mop.collectors import replay
from test_microbatch import Transport

class ReplayPressureTests(unittest.IsolatedAsyncioTestCase):
 async def test_finite_replay_waits_for_capacity(self):
  provider=MicroBatchProvider(Transport(delay=.005),4,0,2,pending_capacity=16)
  engine=await Engine(provider,workers=8,capacity=16,history_limit=32).start()
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'events.jsonl'
   with path.open('w') as stream:
    for i in range(500):stream.write(json.dumps(Event('load','synthetic-load',pid=i).payload())+'\n')
   try:await replay(engine,path)
   finally:await engine.close(10)
  self.assertEqual(engine.stats['raw_events_received'],500)
  self.assertEqual(engine.stats['completed'],500)
  self.assertEqual(engine.stats['raw_dropped_queue_full'],0)
  self.assertEqual(engine.stats['errors'],0)
  self.assertGreater(engine.stats['replay_backpressure_waits'],0)
  self.assertEqual(len(engine.recent),32)
  self.assertLessEqual(provider.stats['peak_active_batches'],2)
