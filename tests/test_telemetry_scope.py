import copy,os,unittest
from pathlib import Path
from mop.core import Event
from mop.pipeline_identity import is_telemetry_write

class TelemetryTests(unittest.TestCase):
    def event(self):
        return Event('security_file_permission','tetragon',metadata={
            'process':{'binary':'/workspace/mop/.runtime/mitmproxy-12.2.3/mitmdump','uid':os.getuid()},
            'outcome':'nonnegative_return','observation':{'function_name':'security_file_permission',
            'args':[{'file_arg':{'path':'/workspace/mop/.runtime/network/tcp/status.tmp'}},{'int_arg':2}],
            'return':{'int_arg':0}}})
    def test_only_owned_proxy_heartbeat_is_excluded(self):
        self.assertTrue(is_telemetry_write(self.event(),Path('/workspace/mop')))
        e=self.event();e.metadata['process']['binary']='/usr/bin/python3'
        self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))
        e=self.event();e.metadata['process']['uid']=os.getuid()+1
        self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))
    def test_business_files_keys_logs_and_failures_stay_visible(self):
        for path in ('/etc/shadow','/workspace/mop/.runtime/network/ca/mitmproxy-ca.pem','/workspace/mop/.runtime/network/events.jsonl','/tmp/status.tmp'):
            e=self.event();e.metadata['observation']['args'][0]['file_arg']['path']=path
            self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))
        e=self.event();e.metadata['observation']['return']['int_arg']=-13
        self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))
        e=self.event();e.metadata['observation']['args'][1]['int_arg']=4
        self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))

    def test_malformed_observations_are_not_filtered(self):
        for args in (None, [None, 2], [{'file_arg':None}, {'int_arg':2}]):
            e=self.event();e.metadata['observation']['args']=args
            self.assertFalse(is_telemetry_write(e,Path('/workspace/mop')))
