import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('install_ux',Path(__file__).resolve().parents[1]/'scripts/install.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class InstallUXTests(unittest.TestCase):
    def test_reject_credentials_and_malformed_urls(self):
        for url in ('file:///tmp/model','http://user:password@host','http://host?token=x','http://host:bad','http://host/#fragment'):
            with self.assertRaises(argparse.ArgumentTypeError):installer.model_url(url)
        self.assertEqual(installer.model_url('https://model.example/v1/'),'https://model.example/v1')

    def test_model_configuration_preserves_user_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'config').mkdir()
            path=root/'config/mop.json';path.write_text(json.dumps({'classification':{'prompt':'My policy'},'workers':3}))
            with patch.object(installer,'ROOT',root):installer.configure_model('http://127.0.0.1:18936')
            result=json.loads(path.read_text())
            self.assertEqual(result['classification']['prompt'],'My policy')
            self.assertEqual(result['workers'],3)
            self.assertEqual(result['base_url'],'http://127.0.0.1:18936')

    def test_core_only_does_not_request_system_links(self):
        with patch.dict(os.environ,{'PATH':'/usr/bin'}),patch.object(installer,'command') as command:
            self.assertTrue(installer.command_entrypoints(True).endswith('/.local/bin/mop'))
            command.assert_not_called()

    def test_conflicting_command_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp);(target/'mop').write_text('existing')
            with patch.dict(os.environ,{'PATH':temp}),patch.object(installer,'command') as command:
                self.assertTrue(installer.command_entrypoints(system_bin=target).endswith('/.local/bin/mop'))
                command.assert_not_called()
            self.assertEqual((target/'mop').read_text(),'existing')

    def test_existing_path_needs_no_system_links(self):
        with patch.dict(os.environ,{'PATH':str(Path.home()/'.local/bin')}),patch.object(installer,'command') as command:
            self.assertEqual(installer.command_entrypoints(),'mop')
            command.assert_not_called()

    def test_missing_links_are_installed_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ,{'PATH':temp}),patch.object(installer,'command') as command:
                self.assertEqual(installer.command_entrypoints(system_bin=Path(temp)),'mop')
                self.assertEqual(command.call_count,4)
                self.assertTrue(all(call.args[0][:4]==['sudo','-n','ln','-s'] for call in command.call_args_list))

    def test_remote_model_health_requires_explicit_selection(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/"config").mkdir()
            (root/"config/mop.json").write_text(json.dumps({"base_url":"https://model.example/v1"}))
            opener=MagicMock();opener.open.return_value.__enter__.return_value.status=200
            with patch.object(installer,"ROOT",root),patch.object(installer.urllib.request,"build_opener",return_value=opener):
                self.assertEqual(installer.model_status()["status"],"not_probed")
                opener.open.assert_not_called()
                self.assertEqual(installer.model_status(allow_remote=True)["status"],"ready")
                opener.open.assert_called_once_with("https://model.example/health",timeout=3)
