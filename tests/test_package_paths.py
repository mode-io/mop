"""Installed code stays read-only; child commands work outside the source tree."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from mop.paths import runtime_root, python_command


class PackagePathsTests(unittest.TestCase):
    def test_installed_runtime_is_user_owned(self):
        with tempfile.TemporaryDirectory() as work, patch.dict(os.environ, {'MOP_STATE_DIR':work}, clear=True):
            self.assertEqual(runtime_root(Path(work)/'installed'),Path(work)/'runtime')

    def test_source_runtime_is_preserved(self):
        with tempfile.TemporaryDirectory() as work, patch.dict(os.environ, {}, clear=True):
            root=Path(work);(root/'scripts').mkdir();(root/'scripts/env.sh').touch()
            self.assertEqual(runtime_root(root),root/'.runtime')

    def test_explicit_runtime_override(self):
        with patch.dict(os.environ, {'MOP_RUNTIME_DIR':'/tmp/mop-runtime-test'}):
            self.assertEqual(runtime_root(),Path('/tmp/mop-runtime-test'))

    def test_subprocess_import_is_independent_of_cwd(self):
        with tempfile.TemporaryDirectory() as cwd:
            output=subprocess.check_output(python_command('--version'),cwd=cwd,text=True)
            self.assertIn('MOP 0.9.4',output)

    def test_import_ignores_untrusted_pythonpath(self):
        with tempfile.TemporaryDirectory() as cwd:
            (Path(cwd)/'mop.py').write_text('raise RuntimeError("wrong import")')
            output=subprocess.check_output(python_command('--version'),cwd=cwd,text=True,env={**os.environ,'PYTHONPATH':cwd})
            self.assertIn('MOP 0.9.4',output)
