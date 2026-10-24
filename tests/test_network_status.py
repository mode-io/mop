import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('network_status', Path(__file__).resolve().parents[1] / 'scripts/network-status.py')
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)

class StatusTests(unittest.TestCase):
    def test_freshness_rejects_stale_and_future_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            path.write_text('{"updated_at": 100, "status": "running"}')
            self.assertTrue(status.read_status(path, now=105)['status_fresh'])
            self.assertFalse(status.read_status(path, now=111)['status_fresh'])
            self.assertFalse(status.read_status(path, now=99)['status_fresh'])

    def test_malformed_and_oversized_status_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            for content in ('[]', 'null', '{"updated_at": null}', 'x' * 65537):
                path.write_text(content)
                self.assertEqual(status.read_status(path)['status'], 'unavailable')
