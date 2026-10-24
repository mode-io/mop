import asyncio
import json
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from mop.core import Engine,Event
from mop.content import capture_command,text_evidence
from mop.classification import ClassificationProvider
from mop.audit import AuditLog
from mop.proxy import make_server
from support import FixtureProvider
from test_guard import Server

class ContentTests(unittest.IsolatedAsyncioTestCase):
    async def test_capture_output_redaction_and_lifecycle(self):
        engine=await Engine(FixtureProvider()).start()
        code='import sys; print("hello"); print("api_key=FAKE_SECRET",file=sys.stderr); print("-----BEGIN PRIVATE KEY-----"); print("BASE64SECRET"); print("-----END PRIVATE KEY-----")'
        result=await capture_command(engine,[sys.executable,'-c',code],duration=3,window_seconds=.1,passthrough=False)
        await engine.close()
        self.assertEqual(result,0)
        records=list(engine.recent)
        self.assertEqual(records[0]['event']['operation'],'task_started')
        self.assertEqual(records[-1]['event']['operation'],'task_exited')
        outputs=[r['event']['metadata']['output'] for r in records if r['event']['operation']=='task_output_window']
        encoded=json.dumps(outputs)
        self.assertIn('hello',encoded)
        self.assertNotIn('FAKE_SECRET',encoded)
        self.assertNotIn('BASE64SECRET',encoded)
        self.assertIn('stdout',encoded);self.assertIn('stderr',encoded)

    async def test_overlong_line_and_timeout_are_explicit(self):
        engine=await Engine(FixtureProvider()).start()
        code='import time; print("x"*20000,flush=True); time.sleep(5)'
        result=await capture_command(engine,[sys.executable,'-c',code],duration=.2,passthrough=False)
        await engine.close()
        self.assertEqual(result,124)
        self.assertIn('overlong line omitted',json.dumps(list(engine.recent)))

    def test_json_credentials_and_binary_content(self):
        raw=json.dumps({'api_key':'secret with spaces','state':json.dumps({'password':'nested secret'}),'text':'hello','prompt_tokens':[60,59]}).encode()
        evidence=text_evidence(raw)
        self.assertNotIn('secret with spaces',evidence['text'])
        self.assertNotIn('nested secret',evidence['text'])
        self.assertIn('hello',evidence['text'])
        self.assertEqual(json.loads(evidence['text'])['prompt_tokens'],[60,59])
        self.assertEqual(text_evidence(b'a\x00b')['omitted'],'binary content')
        self.assertTrue(text_evidence(b'abcdef',3)['truncated'])

    async def test_exact_prompt_payload_is_logged_without_headers(self):
        provider=ClassificationProvider('http://127.0.0.1',api_key='PRIVATE_HEADER')
        response={'choice':provider.options[0],'probabilities':dict(zip(provider.options,[.9,.05,.05]))}
        with tempfile.TemporaryDirectory() as tmp, Server(response) as server:
            provider=ClassificationProvider(server.url,api_key='PRIVATE_HEADER')
            provider.prompt_log=AuditLog(Path(tmp)/'prompts.jsonl')
            event=Event('test','fixture',metadata={'value':'hello'})
            await provider.infer(event);await provider.aclose()
            log=json.loads((Path(tmp)/'prompts.jsonl').read_text())
            self.assertEqual(log['body'],server.requests[0][1])
            self.assertEqual(log['event_ids'],[event.id])
            self.assertNotIn('PRIVATE_HEADER',json.dumps(log))

    async def test_proxy_passes_original_and_reviews_redacted_copy(self):
        engine=await Engine(FixtureProvider()).start()
        with Server({'result':'ok'}) as upstream:
            with socket.socket() as temporary:
                temporary.bind(('127.0.0.1',0));port=temporary.getsockname()[1]
            proxy=make_server(engine,asyncio.get_running_loop(),upstream.url,port)
            thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
            raw=b'{"state":"hello","api_key":"FAKE_SECRET"}'
            def request(body=raw):
                req=urllib.request.Request('http://127.0.0.1:%d/plugins/vllm-jev/choice'%port,body,{'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=3) as response:return response.read()
            try:
                response=await asyncio.to_thread(request)
                self.assertEqual(json.loads(response),{'result':'ok'})
                self.assertEqual(upstream.requests[0][1]['api_key'],'FAKE_SECRET')
                await engine.queue.join()
                record=engine.recent[-1]
                self.assertEqual(record['event']['operation'],'decision_unit')
                self.assertIn('original_request',record['event']['metadata']['attributes'])
                self.assertNotIn('FAKE_SECRET',json.dumps(record))
                self.assertIn('hello',json.dumps(record))
                response=await asyncio.to_thread(request,b'{"stream":true}')
                self.assertEqual(json.loads(response),{'result':'ok'})
                self.assertEqual(len(upstream.requests),2)
            finally:
                await asyncio.to_thread(proxy.shutdown);proxy.server_close();thread.join()
        await engine.close()

    async def test_proxy_cannot_forward_or_classify_into_itself(self):
        engine=Engine(ClassificationProvider('http://127.0.0.1:18937'))
        with self.assertRaises(ValueError):make_server(engine,asyncio.get_running_loop(),'http://127.0.0.1:18936',18937)
        with self.assertRaises(ValueError):make_server(engine,asyncio.get_running_loop(),'http://127.0.0.1:18937',18937)
