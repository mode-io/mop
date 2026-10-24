import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import zlib
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

export=module('capture_export','capture_export.py')

class ExportTests(unittest.TestCase):
    def test_redaction_before_fragmenting_and_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            e=export.Exporter({'uid':1001,'log_dir':tmp,'source':'network-proxy'})
            e.emit(0,'http_response',{'text':'hello '*1500,'api_key':'not-a-real-key'},complete=True)
            rows=[json.loads(line) for line in Path(tmp,'events.jsonl').read_text().splitlines()]
            value=json.loads(''.join(r['metadata']['evidence']['content_fragment'] for r in rows))
            self.assertEqual(value['text'],'hello '*1500)
            self.assertEqual(value['api_key'],'[REDACTED]')
            self.assertTrue(all(r['source']=='network-proxy' for r in rows))
            self.assertFalse(os.stat(Path(tmp,'events.jsonl')).st_mode&0o077)
    def test_refuse_export_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim=Path(tmp,'victim');victim.write_text('keep')
            Path(tmp,'events.jsonl').symlink_to(victim)
            e=export.Exporter({'uid':1001,'log_dir':tmp})
            with self.assertRaises(OSError):e.emit(0,'http_request',{'text':'x'})
            self.assertEqual(victim.read_text(),'keep')

class ProxyDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        old=os.environ.get('MOP_NETWORK_DIR');os.environ['MOP_NETWORK_DIR']=cls.tmp.name
        try:cls.m=module('mitm_adapter','mitm-adapter.py')
        finally:
            if old is None:os.environ.pop('MOP_NETWORK_DIR',None)
            else:os.environ['MOP_NETWORK_DIR']=old
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_protobuf_wire_values_without_invented_names(self):
        decoded=self.m.protobuf_fields(b'\x0a\x05hello\x10\x96\x01')
        self.assertEqual(decoded['fields'][0],{'number':1,'wire_type':2,'utf8':'hello'})
        self.assertEqual(decoded['fields'][1]['unsigned_varint'],150)
        self.assertFalse(decoded['schema_available'])
    def test_truncated_protobuf_is_rejected(self):
        with self.assertRaises(ValueError):self.m.protobuf_fields(b'\x0a\x20hello')
    def test_compression_and_expansion_bound(self):
        import gzip
        self.assertEqual(self.m.decode(gzip.compress(b'{"text":"hello"}'),'gzip'),{'text':'hello'})
        self.assertEqual(self.m.decode(zlib.compress(b'hello'),'deflate'),'hello')
        with self.assertRaises(ValueError):self.m.decode(gzip.compress(b'x'*(self.m.LIMIT+100)),'gzip')
    def test_sse_callback_forwards_original_bytes(self):
        capture=self.m.Capture();rows=[];capture.emit=lambda kind,evidence,**flags:rows.append((kind,evidence,flags))
        request=SimpleNamespace(method='GET',scheme='https',host='localhost',port=443,path='/stream?token=not-real',http_version='HTTP/2',raw_content=b'',headers={})
        response=SimpleNamespace(headers={'content-type':'text/event-stream'},status_code=200,http_version='HTTP/2',stream=None)
        flow=SimpleNamespace(request=request,response=response,id='observed-flow',metadata={})
        capture.responseheaders(flow)
        chunks=[b'data: {"text":',b'"hello"}\n\n']
        for data in chunks:self.assertEqual(response.stream(data),data)
        self.assertEqual(rows[0][1]['body'],{'text':'hello'})
        self.assertEqual(rows[0][1]['original_request']['path'],'/stream')
        self.assertFalse(rows[0][2]['complete'])

if __name__=='__main__':unittest.main()
