#!/usr/bin/env python3
"""Check bundled proxy codecs and bounded decompression without external traffic."""
import json,os,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source='''import importlib.util,json,os
from pathlib import Path
from mitmproxy import ctx
class Check:
 async def running(self):
  root=Path(os.environ['MOP_CODEC_ROOT'])
  spec=importlib.util.spec_from_file_location('mop_codec_adapter',root/'scripts/mitm-adapter.py')
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  results={}
  for name in ('br','zstd'):
   try:
    if name=='br':
     import brotli
     compress=brotli.compress
    else:
     import zstandard
     compress=zstandard.ZstdCompressor().compress
    value=module.decode(compress(b'{"message":"hello"}'),name)
    bounded=False
    try:module.decode(compress(b'x'*(module.LIMIT+1)),name)
    except ValueError:bounded=True
    results[name]={'decoded':value=={'message':'hello'},'expansion_bounded':bounded}
   except Exception as e:results[name]={'error':type(e).__name__}
  Path(os.environ['MOP_CODEC_RESULT']).write_text(json.dumps(results))
  ctx.master.shutdown()
addons=[Check()]
'''
with tempfile.TemporaryDirectory(dir=ROOT/'.runtime',prefix='codec-check-') as tmp:
    directory=Path(tmp);script=directory/'check.py';script.write_text(source)
    env=os.environ.copy();env.update(MOP_CODEC_ROOT=str(ROOT),MOP_CODEC_RESULT=str(directory/'result.json'),MOP_NETWORK_DIR=str(directory))
    subprocess.run([str(ROOT/'.runtime/mitmproxy-12.2.3/mitmdump'),'-q','--mode','regular@127.0.0.1:0','--set','confdir='+str(directory/'ca'),'-s',str(script)],env=env,check=True,timeout=20)
    result=json.loads((directory/'result.json').read_text());print(json.dumps(result,indent=2))
    (ROOT/'.runtime/network/validation-codecs.json').write_text(json.dumps({'verified_at':time.time(),'all_verified':all(v.get('decoded') and v.get('expansion_bounded') for v in result.values()),'checks':result},indent=2))
    if not all(v.get('decoded') and v.get('expansion_bounded') for v in result.values()):raise SystemExit(1)
