import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

class AdvancedProbeDefaults(unittest.TestCase):
    def test_stack_capture_requires_explicit_flag(self):
        script=Path(__file__).resolve().parents[1]/'scripts/enable-advanced-tetragon.py'
        for enabled in (False,True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                (root/'policies').mkdir();(root/'conf').mkdir()
                policy={'spec':{'kprobes':[{'call':name,'selectors':[{'matchActions':[{'action':'Post','kernelStackTrace':True}]}]} for name in ('sys_openat','sys_ptrace','sys_setns')]}}
                (root/'policies/observe.yaml').write_text(json.dumps(policy))
                real_path=Path
                def local_path(value):
                    return root if str(value)=='/opt/mop-tetragon' else real_path(value)
                with patch('os.geteuid',return_value=0), patch('pathlib.Path',side_effect=local_path), patch('sys.argv',[str(script)]+(['--stacks'] if enabled else [])), patch('subprocess.run') as run, patch('subprocess.check_output',return_value='Listening for events...'):
                    runpy.run_path(str(script),run_name='__main__')
                final=json.loads((root/'policies/observe.yaml').read_text())
                for probe in final['spec']['kprobes']:
                    for selector in probe.get('selectors',[]):
                        for action in selector.get('matchActions',[]):
                            self.assertEqual(action.get('kernelStackTrace',False),enabled)
                run.assert_called_once_with(['systemctl','restart','mop-tetragon.service'],check=True)
