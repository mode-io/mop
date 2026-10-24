import asyncio
import json
import socket
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from mop.core import Engine
from mop.proxy import make_server
from mop.proxy_review import exchange_units
from mop.decision_units import DecisionBudgetError
from support import FixtureProvider


class ReviewUnitsTests(unittest.TestCase):
    @patch("mop.proxy_review.tokenizer", return_value=None)
    def test_every_response_part_has_request_and_redaction(self, unused):
        raw=b'{"messages":[{"role":"user","content":"Translate this report"}],"api_key":"FAKE_SECRET"}'
        body=json.dumps({"text":"line of actual response\n"*800}).encode()
        events=exchange_units(FixtureProvider(),"r1","/v1/chat/completions","http://127.0.0.1",raw,body,200)
        response=[e for e in events if e.metadata["kind"]=="response"]
        self.assertGreater(len(response),1)
        self.assertEqual("".join(e.metadata["content"] for e in response),body.decode())
        for event in response:
            text=event.metadata["attributes"]["original_request"]
            self.assertIn("Translate this report",text)
            self.assertNotIn("FAKE_SECRET",text)
        self.assertNotIn("FAKE_SECRET",json.dumps([e.payload() for e in events]))

    @patch("mop.proxy_review.tokenizer", return_value=None)
    def test_large_request_is_not_silently_removed(self, unused):
        with self.assertRaises(DecisionBudgetError):
            exchange_units(FixtureProvider(),"r1","/v1/chat/completions","http://127.0.0.1",
                           json.dumps({"prompt":"word "*2000}).encode(),b'{"text":"ok"}',200)


class LiveProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_sse_forwarding_and_review_endpoint(self):
        stream=b'data: {"choices":[{"delta":{"content":"actual transport"}}]}\n\ndata: [DONE]\n\n'
        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200);self.send_header("Content-Type","text/event-stream");self.end_headers()
                for offset in range(0,len(stream),7):
                    self.wfile.write(stream[offset:offset+7]);self.wfile.flush()
            def log_message(self,*args):pass
        upstream=ThreadingHTTPServer(("127.0.0.1",0),Upstream)
        ut=threading.Thread(target=upstream.serve_forever,daemon=True);ut.start()
        engine=await Engine(FixtureProvider()).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        proxy=make_server(engine,asyncio.get_running_loop(),
                          f"http://127.0.0.1:{upstream.server_port}",port)
        pt=threading.Thread(target=proxy.serve_forever,daemon=True);pt.start()
        def request(path, data=None):
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(urllib.request.Request(f"http://127.0.0.1:{port}"+path,data=data),timeout=5) as r:
                return r.read()
        try:
            result=await asyncio.to_thread(request,"/v1/chat/completions",b'{"stream":true,"prompt":"summarize"}')
            self.assertEqual(result,stream)
            await engine.queue.join()
            report=json.loads(await asyncio.to_thread(request,"/mop/reviews"))
            self.assertFalse(report["review_gaps"])
            response=[r for r in report["reviews"] if r["kind"]=="response"]
            self.assertTrue(response)
            self.assertIn("summarize",response[0]["input"]["attributes"]["original_request"])
        finally:
            await asyncio.to_thread(proxy.shutdown);proxy.server_close();pt.join()
            await asyncio.to_thread(upstream.shutdown);upstream.server_close();ut.join()
            await engine.close()


if __name__=="__main__":unittest.main()
