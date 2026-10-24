"""Reproducible retention/memory/UI stress and optional local Jev burst tests."""
import argparse,asyncio,json,os,resource,statistics,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from mop.core import Engine,Event,Verdict
from mop.ui_state import ViewState

class Fixture:
    name='retention-fixture'
    async def infer(self,event):
        return Verdict('normal','Synthetic stress fixture',self.name,.9,
                       probabilities={'normal':.9,'suspicious':.08,'high_risk':.02})

def rss():
    return int(Path('/proc/self/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')

def make_event(index,identities,payload,nested=False):
    pid=100000+index%identities
    event = Event('process_review','stress-fixture',pid,pid,'fixture',metadata={
        'start_ticks':1,'runtime_evidence':{'scope':'synthetic stress data',
        'logs':[{'tail':('progress '+str(index)+' '+('x'*payload))}]}})
    if nested:
        event.metadata['runtime_evidence'] = {
            'scope':'synthetic bounded runtime fixture','captured_at':time.time(),
            'process':{'name':'fixture','state':'S','ppid':1,'cpu_ticks':index,'start_ticks':1,'exe':'/usr/bin/python3','cwd':'/workspace/task'},
            'status':{key:str(index) for key in ('Uid','Gid','Threads','VmRSS','VmSize','CapEff','NoNewPrivs','Seccomp','TracerPid')},
            'io':{key:str(index) for key in ('rchar','wchar','read_bytes','write_bytes','syscr','syscw')},
            'fds':[{'fd':str(i),'target':'/workspace/task/output-'+str(i)+'.log'} for i in range(16)],
            'logs':[{'source':'explicit_task_log','status':'ok','tail':'progress '+str(index)+' '+'x'*800,'truncated':True} for _ in range(3)],
            'gaps':['Environment not collected.','Pipes not consumed.','Evidence is incomplete.'],
            'changes':{'elapsed_seconds':30,'cpu_ticks_delta':3,'io_delta':{'read_bytes':100,'write_bytes':200}}}
    return event

def rows(n):
    return [dict(pid=100000+i,tid=100000+i,start_ticks=1,comm='fixture',user='fixture',
                 cpu=1,rss_mb=10,ticks=1,ppid=1,state='S') for i in range(n)]

async def memory_trial(args):
    before=rss(); start=time.perf_counter()
    engine=await Engine(Fixture(),workers=8,capacity=256,history_limit=args.history).start()
    display_rows = rows(min(args.identities,512))
    for offset in range(0,args.events,128):
        if args.prune_live:
            end = min(offset + 128, args.events)
            ids = list(dict.fromkeys(i % args.identities for i in range(max(0, end - min(args.identities,512)), end)))
            display_rows = [dict(rows(1)[0], pid=100000+i, tid=100000+i) for i in ids]
            engine.retain_visible_identities(display_rows)
        for i in range(offset,min(offset+128,args.events)):
            engine.submit(make_event(i,args.identities,args.payload,args.nested))
        await engine.queue.join()
    await engine.close()
    elapsed=time.perf_counter()-start
    retained=rss()
    unique={id(record):record for record in [*engine.recent,*engine.latest_advice.values()]}
    sizes=[len(json.dumps(record).encode()) for record in list(unique.values())[:256]]
    timings=[]; state=ViewState()
    for _ in range(3):
        begin=time.perf_counter();state.visible(display_rows,engine.recent,engine.latest_advice.values())
        timings.append((time.perf_counter()-begin)*1000)
    return {'kind':'retention','history_limit':args.history,'prune_live':args.prune_live,'events':args.events,
            'identities':args.identities,'payload_bytes':args.payload,'nested':args.nested,'completed':engine.stats['completed'],
            'recent_count':len(engine.recent),'latest_count':len(engine.latest_advice),
            'unique_retained_records':len(unique),'rss_delta_mib':(retained-before)/1048576,
            'rss_total_mib':retained/1048576,'peak_rss_mib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
            'serialized_record_mean_bytes':statistics.mean(sizes),
            'ui_rows':min(args.identities,512),'visible_ms_median':statistics.median(timings),
            'wall_seconds':elapsed,'fixture_throughput_rps':args.events/elapsed}

async def model_trials():
    from mop.classification import ClassificationProvider,DEFAULT_TASK
    from mop.microbatch import MicroBatchProvider
    results=[]
    for count,capacity in [(8,256),(32,256),(128,256),(512,64)]:
        transport=ClassificationProvider('http://127.0.0.1:18936',timeout=20,cache_policy='native')
        provider=MicroBatchProvider(transport,4,0,2,pending_capacity=8)
        engine=await Engine(provider,workers=8,capacity=capacity,history_limit=4096).start()
        start=time.perf_counter()
        for index in range(count):engine.submit(make_event(index,count,4500))
        await engine.close(60)
        elapsed=time.perf_counter()-start
        results.append({'kind':'native_jev_burst','offered':count,'capacity':capacity,
                        'wall_seconds':elapsed,'completed_rps':engine.stats['completed']/elapsed,
                        'summary':engine.summary()})
        print(json.dumps(results[-1]),flush=True)
    return results

async def main(args):
    if args.child:
        print(json.dumps(await memory_trial(args)));return
    results=[]
    for identities in (128,12000):
        for history in (100,4096,8192,16384):
            command=[sys.executable,__file__,'--child','--history',str(history),'--identities',str(identities),
                     '--events','20000','--payload','4500']
            if args.prune_live:command.append("--prune-live")
            if args.nested:command.append("--nested")
            result=json.loads(subprocess.check_output(command,text=True,timeout=120))
            results.append(result);print(json.dumps(result),flush=True)
    if args.model:results+=await model_trials()
    Path(args.output).write_text(json.dumps({'results':results,'notes':[
        'Synthetic memory workload; fixture throughput is not model throughput.',
        'Native model uses shared live server with background observers; no isolation claimed.',
        'Repeated synthetic inputs may benefit from prefix caching; no accuracy claims.',
        'RSS includes allocator behavior; serialized size is not Python heap size.']},indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--child',action='store_true')
    parser.add_argument('--prune-live',action='store_true')
    parser.add_argument('--nested',action='store_true')
    parser.add_argument('--model',action='store_true');parser.add_argument('--history',type=int,default=4096)
    parser.add_argument('--identities',type=int,default=128);parser.add_argument('--events',type=int,default=20000)
    parser.add_argument('--payload',type=int,default=4500);parser.add_argument('--output',default='artifacts/retention-stress.json')
    asyncio.run(main(parser.parse_args()))
