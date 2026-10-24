import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

agent=load('content_agent','content-agent.py')
installer=load('mop_installer','install.py')

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.a=agent.Agent({'uid':1001,'log_dir':self.tmp.name})
        self.a.excluded=lambda pid:False
        self.a.lifetime=lambda pid,fallback:1
        self.events=[]
        self.a.emit=lambda pid,kind,evidence,**flags:self.events.append((kind,evidence,flags))

    def tearDown(self):
        self.a.logger.removeHandler(self.a.writer);self.a.writer.close();self.tmp.cleanup()

    def test_successful_stdout_only(self):
        self.a.stdio('MOPW 20 20 100 1 6 hello\\x0a')
        self.assertEqual(self.events,[])
        self.a.stdio('MOPR 20 20 100 6')
        self.assertEqual(self.events[0][1]['text'],'hello\n')
        self.a.stdio('MOPW 20 20 101 1 6 hello\\x0a')
        self.a.stdio('MOPR 20 20 101 -1')
        self.assertEqual(len(self.events),1)

    def test_truncated_write_never_claims_complete_text(self):
        self.a.stdio('MOPW 20 20 100 1 9000 '+'x'*192)
        for offset in range(192,3072,192):self.a.stdio('MOPX 20 20 100 %d '%offset+'x'*192)
        self.a.stdio('MOPR 20 20 100 9000')
        self.assertNotIn('text',self.events[0][1])
        self.assertTrue(self.events[0][2]['truncated'])

    def test_http_body_reassembled_and_credentials_not_exported(self):
        record={'pid':20,'fd':1,'tuple':'ssl-object','direction':'WRITE'}
        data=b'POST /v1/chat?api_key=fake HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fake\r\nContent-Length: 19\r\n\r\n{"message":"hello"}'
        self.a.tls_payload(record,data[:-4]);self.assertEqual(self.events,[])
        self.a.tls_payload(record,data[-4:])
        evidence=self.events[0][1]
        self.assertEqual(evidence['body'],{'message':'hello'})
        self.assertEqual(evidence['path'],'/v1/chat')
        self.assertNotIn('fake',json.dumps(evidence))

    def test_chunked_body_reassembled(self):
        self.a.tls_payload({'pid':20,'fd':1,'tuple':'ssl-object','direction':'READ'},
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n')
        self.assertEqual(self.events[0][1]['body'],'hello')

    def test_redaction_and_ambiguous_encoding(self):
        clean=agent.redact({'api_key':'fake-secret','body':'Bearer abc123','nested':{'password':'fake'}})
        self.assertEqual(clean['api_key'],'[REDACTED]')
        self.assertNotIn('abc123',json.dumps(clean))
        self.assertEqual(agent.decode_buffer('hello\\x0a',6),b'hello\n')
        with self.assertRaises(ValueError):agent.decode_buffer('hello\\x0a',9)

    def test_tls_gap_suppresses_connection(self):
        self.a.stdio('MOPG 20 1 9000')
        self.a.tls_payload({'pid':20,'fd':1,'tuple':'ssl-object','direction':'WRITE'},b'GET / HTTP/1.1\r\n\r\n')
        self.assertEqual([row[0] for row in self.events],['capture_gap'])

    def test_offline_checksum_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'bad.tar.gz').write_bytes(b'wrong')
            with patch.object(installer,'ROOT',path):
                with self.assertRaises(ValueError):installer.download(path,'bad.tar.gz','https://github.com/example','0'*64,True)

    def test_model_health_redirect_rejected(self):
        self.assertIsNone(installer.NoRedirect().redirect_request(None,None,302,'',{},'http://example.com'))

    def test_model_projection_has_no_synthetic_context(self):
        from mop.core import Event
        from mop.input_projection import project
        event=Event.from_dict({'source':'system-content','operation':'captured_io','metadata':{
            'uid':1001,'observed_pid':20,'kind':'stdio','collector_id':'internal-id','sequence':22,
            'evidence':{'text':'hello\n'},'capture_status':{'truncated':False}}})
        result=project(event)
        self.assertEqual(result['evidence']['text'],'hello\n')
        self.assertNotIn('internal-id',json.dumps(result))
        self.assertFalse(result.get('context'))

if __name__=='__main__':unittest.main()
