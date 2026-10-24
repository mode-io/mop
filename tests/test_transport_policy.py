import asyncio,copy,json,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from mop.classification import ClassificationProvider,DEFAULT_TASK
from mop.core import Event,Verdict
from mop.microbatch import MicroBatchProvider

class Server:
 def __init__(self,status=200,close_first=False):
  outer=self;self.requests=[];self.ports=[]
  class Handler(BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def do_POST(self):
    value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
    outer.requests.append(value);outer.ports.append(self.client_address[1])
    requests=value.get('requests',[value])
    results=[{'choice':r['options'][0],'probabilities':dict(zip(r['options'],[1.0]+[0.0]*(len(r['options'])-1)))} for r in requests]
    body=results[0] if 'requests' not in value else {'results':results,'decision_count':len(results)}
    data=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    if close_first and len(outer.requests)==1:self.close_connection=True
   def log_message(self,*args):pass
  self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
  self.url='http://127.0.0.1:'+str(self.server.server_port)
 def __enter__(self):
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();return self
 def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join()

class PolicyTests(unittest.IsolatedAsyncioTestCase):
 async def test_keepalive_and_close(self):
  with Server() as server:
   p=ClassificationProvider(server.url)
   try:
    for _ in range(3):await p.infer(Event('read','test'))
    self.assertEqual(len(set(server.ports)),1)
    self.assertEqual(p.summary()['connections_created'],1)
    self.assertEqual(p.summary()['connections_reused'],2)
   finally:await p.aclose()
   self.assertEqual(p.summary()['idle_connections'],0)
 async def test_stale_keepalive_reconnects_once(self):
  with Server(close_first=True) as server:
   p=ClassificationProvider(server.url)
   try:
    await p.infer(Event('a','test'));await asyncio.sleep(.03)
    await p.infer(Event('b','test'))
    self.assertEqual(len(server.requests),2)
    self.assertEqual(p.summary()['stale_connection_retries'],1)
   finally:await p.aclose()
 def test_endpoint_is_immutable_after_validation(self):
  p=ClassificationProvider('http://127.0.0.1')
  with self.assertRaises(AttributeError):p.base_url='http://elsewhere.invalid'
 async def test_mixed_policy_batch_decodes_each_options_list(self):
  task=copy.deepcopy(DEFAULT_TASK);task['prompt']='Assess function artifact risk'
  for c in task['categories']:c['description']='Function-specific '+c['label']
  with Server() as server:
   p=ClassificationProvider(server.url,function_task=task)
   try:results=await p.infer_batch([Event('read','proc-poll'),Event('python_function_execution','viztracer')])
   finally:await p.aclose()
   requests=server.requests[0]['requests']
   self.assertEqual(requests[0]['question'],DEFAULT_TASK['prompt'])
   self.assertEqual(requests[1]['question'],task['prompt'])
   self.assertNotEqual(requests[0]['options'],requests[1]['options'])
   self.assertEqual([r.category for r in results],['normal','normal'])
 async def test_redirects_are_not_followed(self):
  with Server(status=302) as server:
   p=ClassificationProvider(server.url)
   try:
    with self.assertRaises(ValueError):await p.infer(Event('test','test'))
    self.assertEqual(len(server.requests),1)
   finally:await p.aclose()
 def test_incompatible_labels_rejected(self):
  task=copy.deepcopy(DEFAULT_TASK);task['categories'][0]['label']='different'
  with self.assertRaises(ValueError):ClassificationProvider('http://127.0.0.1',function_task=task)
 async def test_invalid_batch_does_not_partially_complete(self):
  class Transport:
   name='fixture'
   async def infer_batch(self,events):return [Verdict('normal','test','fixture'),None]
   def summary(self):return {}
  p=MicroBatchProvider(Transport(),2,1,1)
  try:
   answers=await asyncio.gather(p.infer(Event('a','test')),p.infer(Event('b','test')),return_exceptions=True)
   self.assertTrue(all(isinstance(answer,ValueError) for answer in answers))
  finally:await p.aclose()
