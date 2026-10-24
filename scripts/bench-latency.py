"""Replay a fixed private corpus against the local Jev guard for latency comparisons."""
import argparse
import asyncio
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from mop.classification import ClassificationProvider
from mop.core import Event,percentile
from mop.microbatch import MicroBatchProvider
from mop.model_slots import state_root


def corpus():
    path=ROOT/'.runtime/perf-corpus.json'
    if not path.exists():
        observed=deque(maxlen=2048)
        paths=[p for p in state_root().glob('decisions.jsonl*') if not p.name.endswith('.lock')]
        for source in sorted(paths,key=lambda p:p.stat().st_mtime):
            with source.open() as stream:
                for line in stream:
                    try:observed.append(json.loads(line)['event'])
                    except (ValueError,KeyError):continue
        if len(observed)<24:raise ValueError('Capture at least 24 daemon decisions before benchmarking')
        ordered=sorted(observed,key=lambda e:len(json.dumps(e)))
        selected=[]
        for i in range(8):selected.extend([ordered[2*i],ordered[-8+i],ordered[2*i+1]])
        path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(selected,stream)
    raw=path.read_bytes()
    return raw,[Event(**value) for value in json.loads(raw)]


async def main(args):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',args.label):raise ValueError('Use an alphanumeric run label')
    raw,events=corpus()
    transport=ClassificationProvider('http://127.0.0.1:18936',input_mode='compact',artifact_rules=True)
    transport.native_batch_size=args.native_batch_size
    transport.input_token_budget=args.input_budget
    provider=MicroBatchProvider(transport,args.batch_size,0,2,pending_capacity=16)
    try:
        await provider.infer(events[0])
        semaphore=asyncio.Semaphore(8);results=[];start=time.monotonic()
        async def run(index,event):
            offered=time.monotonic()
            async with semaphore:
                began=time.monotonic();verdict=await provider.infer(event)
                results.append({'index':index,'category':verdict.category,'latency_ms':(time.monotonic()-began)*1000,
                                'total_ms':(time.monotonic()-offered)*1000,'fragments':verdict.timing.get('input_fragments',1)})
        await asyncio.gather(*(run(i,event) for i,event in enumerate(events)))
        elapsed=time.monotonic()-start
        report={'label':args.label,'corpus_sha256':hashlib.sha256(raw).hexdigest(),'events':len(events),
                'batch_size':args.batch_size,'native_batch_size':args.native_batch_size,'input_token_budget':args.input_budget,
                'concurrency':8,'seconds':elapsed,'events_per_second':len(events)/elapsed,
                'p50_ms':percentile([v['latency_ms'] for v in results],.5),
                'p95_ms':percentile([v['latency_ms'] for v in results],.95),
                'end_to_end_p95_ms':percentile([v['total_ms'] for v in results],.95),
                'unknown':sum(r['category']=='unknown' for r in results),'results':sorted(results,key=lambda r:r['index']),
                'batching':provider.summary()}
        destination=ROOT/'artifacts'/('latency-'+args.label+'.json');destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k not in ('results','batching')}))
    finally:await provider.aclose()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--batch-size',type=int,choices=range(1,17),default=4)
    parser.add_argument('--native-batch-size',type=int,choices=range(1,17),default=8)
    parser.add_argument('--input-budget',type=int,choices=(1024,2048,3072),default=3072)
    asyncio.run(main(parser.parse_args()))
