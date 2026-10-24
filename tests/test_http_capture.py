import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('content_agent',ROOT/'scripts/content-agent.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.a=m.Agent({'uid':1001,'log_dir':self.tmp.name})
        self.a.excluded=lambda pid:False
        self.a.lifetime=lambda pid,fallback:123
        self.rows=[]
        self.a._write=lambda pid,kind,evidence,flags:self.rows.append({'kind':kind,'evidence':evidence,'flags':flags})
    def tearDown(self):
        self.a.logger.removeHandler(self.a.writer);self.a.writer.close();self.tmp.cleanup()
    def feed(self,data,direction='READ',connection=1,stride=None):
        r={'pid':20,'fd':connection,'tuple':'ssl-object','direction':direction}
        stride=stride or max(1,len(data))
        for i in range(0,len(data),stride):self.a.tls_payload(r,data[i:i+stride])
    def request(self,body=b'{"question":"hello"}',connection=1):
        self.feed(b'POST /chat HTTP/1.1\r\nHost: example.org\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body,'WRITE',connection)
    def test_chunked_one_byte_segments_and_request_context(self):
        self.request()
        self.feed(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: ignored\r\n\r\n',stride=1)
        row=self.rows[-1];self.assertEqual(row['kind'],'http_response')
        self.assertEqual(row['evidence']['body'],'hello world')
        self.assertEqual(row['evidence']['original_request']['body'],{'question':'hello'})
        self.assertEqual(row['evidence']['request_id'],self.rows[0]['evidence']['request_id'])
    def test_sse_emitted_before_response_finishes(self):
        self.request()
        self.feed(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
        data=b'data: {"text":"hello"}\r\n\r\n'
        self.feed(hex(len(data))[2:].encode()+b'\r\n'+data+b'\r\n',stride=1)
        self.assertEqual(self.rows[-1]['kind'],'http_response_event')
        self.assertEqual(self.rows[-1]['evidence']['body'],{'text':'hello'})
        self.assertFalse(self.rows[-1]['flags']['complete'])
        self.feed(b'0\r\n\r\n')
        self.assertEqual(self.rows[-1]['kind'],'http_response_end')
        self.assertTrue(self.rows[-1]['flags']['complete'])
    def test_connections_do_not_cross_associate(self):
        self.request(b'{"question":"A"}',1);self.request(b'{"question":"B"}',2)
        wire=b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx'
        self.feed(wire,connection=2);self.feed(wire,connection=1)
        self.assertEqual([r['evidence']['original_request']['body']['question'] for r in self.rows if r['kind']=='http_response'],['B','A'])
    def test_keep_alive_pipeline_and_interim(self):
        self.request(b'"one"');self.request(b'"two"')
        self.feed(b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb')
        rows=[r for r in self.rows if r['kind']=='http_response' and r['evidence']['status']==200]
        self.assertEqual([r['evidence']['original_request']['body'] for r in rows],['one','two'])
    def test_malformed_and_ambiguous_framing_fail_closed(self):
        self.request()
        self.feed(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx')
        self.assertEqual(self.rows[-1]['kind'],'capture_gap')
        self.assertFalse(any(r['kind']=='http_response' for r in self.rows))
    def test_gap_and_ssl_free_do_not_reuse_request(self):
        self.request();self.a.stdio('MOPG 20 1 9000')
        self.a.stdio('MOPC 20 1')
        self.feed(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx')
        self.assertFalse(self.rows[-1]['flags']['request_context_captured'])
    def test_long_body_roundtrip_and_redaction_before_slicing(self):
        original={'text':'hello world '*1500,'api_key':'fake-secret-value'}
        self.request(json.dumps(original).encode())
        fragments=[r['evidence'] for r in self.rows if 'content_fragment' in r['evidence']]
        restored=json.loads(''.join(r['content_fragment'] for r in fragments))
        self.assertEqual(restored['body']['text'],original['text'])
        self.assertEqual(restored['body']['api_key'],'[REDACTED]')
        self.assertNotIn('fake-secret-value',json.dumps(self.rows))
        self.assertTrue(all(len(json.dumps(r))<6500 for r in self.rows))
    def test_large_request_context_is_explicitly_partial(self):
        self.request(json.dumps({'text':'x'*5000}).encode())
        self.feed(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        row=self.rows[-1]
        self.assertTrue(row['flags']['request_context_partial'])
        self.assertTrue(row['evidence']['original_request']['body_omitted'])
    def test_fragmented_stdout_reassembles_before_export(self):
        data=b'hello '*700+b'\n';stamp=100
        def encoded(x):return ''.join(chr(c) if 32<=c<=126 else '\\x%02x'%c for c in x)
        for sequence,block in enumerate((data[:2100],data[2100:])):
            stamp=100+sequence
            self.a.stdio(f'MOPW 20 20 {stamp} 1 {len(block)} '+encoded(block[:192]))
            for offset in range(192,len(block),192):self.a.stdio(f'MOPX 20 20 {stamp} {offset} '+encoded(block[offset:offset+192]))
            self.a.stdio(f'MOPR 20 20 {stamp} {len(block)}')
        evidence=json.loads(''.join(r['evidence']['content_fragment'] for r in self.rows))
        self.assertEqual(evidence['text'],data.decode())
    def test_loss_marks_following_stdout_incomplete(self):
        self.a.stdio('MOPW 20 20 10 1 4 head')
        self.a.stdio('MOPR 20 20 10 4')
        self.a.stdio('MOPD 1')
        self.a.stdio('MOPW 20 20 11 1 5 tail\\x0a')
        self.a.stdio('MOPR 20 20 11 5')
        self.assertTrue(self.rows[-1]['flags']['preceding_bytes_missing'])

    def test_process_identity_survives_exit_during_export(self):
        stat='20 (example) '+' '.join(['0']*19+['123'])
        with patch.object(m.Path,'read_text',side_effect=[stat,FileNotFoundError()]):
            self.assertEqual(m.Agent.lifetime(self.a,20,0),123)
            self.assertEqual(m.Agent.lifetime(self.a,20,0),123)
        with patch.object(m.Path,'read_text',return_value=stat[:-3]+'456'):
            self.assertEqual(m.Agent.lifetime(self.a,20,0),456)

    def test_perf_loss_invalidates_http2_state(self):
        self.a.h2_sessions[(20,123,1,'ssl')]=object()
        self.a.stdio('Lost 2 events')
        self.assertEqual(self.a.stats['perf_loss_gaps'],2)
        self.assertFalse(self.a.h2_sessions)
        self.assertEqual(self.rows[-1]['kind'],'capture_gap')

    def test_parser_pressure_retains_bounded_state(self):
        self.a._write=lambda *args:None
        for _ in range(1000):
            self.request(b'{"text":"ordinary content"}')
            self.feed(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n')
        self.assertEqual(sum(len(q) for q in self.a.requests.values()),0)
        self.assertEqual(len(self.a.http),2)
        self.assertTrue(all(not parser.buffer for parser in self.a.http.values()))

    def test_bounded_oversize_and_unknown_encoding(self):
        self.feed(b'HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n')
        self.assertEqual(self.rows[-1]['kind'],'capture_gap')
        self.assertTrue(self.a.stats['http_body_limit_gaps'])

if __name__=='__main__':unittest.main()
