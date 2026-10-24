import asyncio,json,sys,tempfile,unittest
from pathlib import Path
from mop.core import Engine
from mop.viztracer_capture import capture_python,script_command
from mop.cli import parser
from support import FixtureProvider

class SelectionTests(unittest.TestCase):
 def test_default_and_optout(self):
  self.assertTrue(parser().parse_args(['capture','--','python','job.py']).viztracer)
  self.assertFalse(parser().parse_args(['capture','--no-viztracer','--','python','job.py']).viztracer)
 def test_non_script_commands_not_rewritten(self):
  self.assertIsNone(script_command(['bash','-c','echo hello']))
  self.assertIsNone(script_command([sys.executable,'-c','print(1)']))

class RuntimeTests(unittest.IsolatedAsyncioTestCase):
 async def execute_script(self,source,enabled=True,limit=256):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'job.py';path.write_text(source)
   engine=await Engine(FixtureProvider(),capacity=4).start()
   try:status=await capture_python(engine,[sys.executable,str(path)],duration=10,passthrough=False,enabled=enabled,max_functions=limit)
   finally:await engine.close()
   return status,engine
 async def test_real_inputs_steps_and_return(self):
  status,engine=await self.execute_script("def clean(text):\n result=text.strip().upper()\n return result\nprint(clean(' hello '))\n")
  self.assertEqual(status,0)
  functions=[r['event'] for r in engine.recent if r['event']['source']=='viztracer']
  self.assertEqual(len(functions),1)
  m=functions[0]['metadata']
  self.assertEqual(m['input_arguments_repr']['text'],"' hello '")
  self.assertIn('HELLO',m['return_value_repr'])
  self.assertTrue(m['assignment_steps'])
  self.assertEqual(functions[0]['context'],{})
  output=[r['event'] for r in engine.recent if r['event']['operation']=='task_output_window']
  self.assertIn('HELLO',json.dumps(output))
  self.assertNotIn('Saving trace data',json.dumps(output))
 async def test_threadpool_capture(self):
  status,engine=await self.execute_script("from concurrent.futures import ThreadPoolExecutor\ndef work(text):\n result=text.upper()\n return result\nwith ThreadPoolExecutor(2) as pool:\n print(list(pool.map(work,['one','two'])))\n")
  observed=[r['event']['metadata'] for r in engine.recent if r['event']['source']=='viztracer']
  self.assertEqual(status,0)
  self.assertEqual(len([m for m in observed if m['function']=='work']),2)
 async def test_optout_has_no_internal_events(self):
  status,engine=await self.execute_script('def f(): return 1\nprint(f())\n',enabled=False)
  self.assertEqual(status,0)
  self.assertFalse(any(r['event']['source']=='viztracer' for r in engine.recent))
 async def test_exit_code_preserved(self):
  status,engine=await self.execute_script('raise SystemExit(7)\n')
  self.assertEqual(status,7)
 async def test_explicit_budget_gap(self):
  status,engine=await self.execute_script('def f(x): return x\nfor i in range(8): f(i)\n',limit=2)
  self.assertEqual(status,0)
  self.assertEqual(engine.stats['viztracer_function_events'],2)
  self.assertEqual(engine.stats['viztracer_unreviewed_functions'],6)
  self.assertEqual(engine.stats['log_errors'],1)
 async def test_top_level_script_still_runs(self):
  status,engine=await self.execute_script('print("plain")\n')
  self.assertEqual(status,0)
  self.assertEqual(engine.stats['viztracer_no_function_calls'],1)
