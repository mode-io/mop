import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'examples/security_lab/worker.py'

class BoundaryTests(unittest.TestCase):
    def test_refuses_fixture_outside_runtime_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'artifacts') as directory:
            root=Path(directory)
            (root/'.mop-lab').write_text('synthetic-only')
            scratch=root/'scratch.txt';scratch.write_text('unchanged')
            result=subprocess.run([sys.executable,str(WORKER),str(root),'1','0'],capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(scratch.read_text(),'unchanged')

    def test_symlink_cannot_escape_lab(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.runtime') as directory, tempfile.TemporaryDirectory(dir=ROOT/'artifacts') as outside:
            root=Path(directory);(root/'.mop-lab').write_text('synthetic-only')
            target=Path(outside)/'keep.txt';target.write_text('unchanged')
            (root/'scratch.txt').symlink_to(target)
            result=subprocess.run([sys.executable,str(WORKER),str(root),'1','0'],capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(target.read_text(),'unchanged')

    def test_expected_labels_are_not_model_inputs(self):
        for line in (ROOT/'examples/security_lab/events.jsonl').read_text().splitlines():
            event=json.loads(line)
            self.assertNotIn('expected',event)
            self.assertNotIn('expected',event['metadata'])
            self.assertNotIn('verdict',event)

class ObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_transfer_is_real_but_uses_only_dummy_data_and_local_sink(self):
        spec=importlib.util.spec_from_file_location('lab',ROOT/'scripts/evaluate-security-lab.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=ROOT/'.runtime') as directory:
            result=await module.collect_case(Path(directory),4,0)
            self.assertEqual(result['worker_exit'],0)
            self.assertTrue(result['verification']['receipt_matches_account_file'])
            self.assertTrue(any(e['event']=='urllib.Request' for e in result['verification']['python_audit_events']))
            self.assertIn('combined',result['events'])
