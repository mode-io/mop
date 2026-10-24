"""Core-first classification, scoped specialists, and non-voting shadow slots."""
import asyncio
import copy
from collections import Counter, deque
import time
from .core import Verdict, percentile
from .model_slots import Registry, LABELS, revision

class ModelRouter:
    name='vllm-jev'
    def __init__(self, factory, task, default, registry=None):
        self.factory=factory;self.task=copy.deepcopy(task)
        self.labels=tuple(c['label'] for c in task['categories'])
        self.registry=registry or Registry(default)
        self.generation=None;self.retired=[];self.next_read=0;self.reload_error=''
        self.metrics={};self.reload(force=True)
    def reload(self, force=False):
        if not force and time.monotonic()<self.next_read:return
        self.next_read=time.monotonic()+1
        try:
            value=self.registry.read();key=revision(value)
            if self.generation and self.generation['revision']==key:return
            if len(self.retired)>8:raise ValueError('Too many in-flight model revisions')
            task=copy.deepcopy(self.task)
            rules=[r for r in value['rules'] if r['enabled']]
            if rules:
                task['prompt']+='\nOperator review policy (apply to observed facts; do not invent missing context):\n'+'\n'.join(r['id']+': '+r['text'] for r in rules)
            from .classification import validate_task
            validate_task(task)
            if len(value['models'])>1 and self.labels!=LABELS:raise ValueError('Multi-model routing requires normal/suspicious/high_risk categories')
            providers={s['name']:self.factory(s,task) for s in value['models'] if s['state']!='disabled'}
            new={'revision':key,'config':value,'providers':providers,'active':0}
            if self.generation:self.retired.append(self.generation)
            self.generation=new;self.reload_error=''
        except Exception as error:
            self.reload_error=type(error).__name__
            if self.generation is None:raise
    async def infer(self,event):
        self.reload();generation=self.generation;generation['active']+=1
        traces=[]
        async def call(slot):
            begin=time.monotonic();error=''
            try:
                verdict=await asyncio.wait_for(generation['providers'][slot['name']].infer(event),slot['budget_ms']/1000)
            except asyncio.TimeoutError:
                error='budget_exceeded';verdict=Verdict('unknown','Model time budget exceeded',slot['name'])
            except Exception as failure:
                error=type(failure).__name__;verdict=Verdict('unknown','Model request failed',slot['name'])
            elapsed=(time.monotonic()-begin)*1000
            metric=self.metrics.setdefault((generation['revision'],slot['name']),{'counts':Counter(),'latency':deque(maxlen=512),'started':time.monotonic()})
            metric['counts']['calls']+=1;metric['counts'][verdict.category]+=1
            if error:metric['counts'][error]+=1
            metric['latency'].append(elapsed)
            traces.append({'name':slot['name'],'version':slot['version'],'model':slot['model'],'state':slot['state'],'category':verdict.category,'confidence':verdict.confidence,'latency_ms':elapsed,'budget_ms':slot['budget_ms'],'reason':verdict.reason,'error':error})
            return verdict
        try:
            core=next(s for s in generation['config']['models'] if s['role']=='core')
            result=await call(core)
            others=[s for s in generation['config']['models'] if s['role']=='specialist' and s['state']!='disabled' and
                    (event.source in s['sources'] or (not s['sources'] and result.category!='normal'))]
            verdicts=await asyncio.gather(*(call(s) for s in others))
            votes=[result]+[v for s,v in zip(others,verdicts) if s['state']=='active']
            order={'normal':0,'suspicious':1,'unknown':2,'high_risk':3}
            selected=max(votes,key=lambda v:order.get(v.category,0)) if others else result
            selected=copy.deepcopy(selected)
            selected.guard_trace=traces
            selected.policy_revision=generation['revision']
            selected.policy_rules=[r['id'] for r in generation['config']['rules'] if r['enabled']]
            for s,v in zip(others,verdicts):
                if s['state']=='shadow' and v.category!=result.category:self.metrics[(generation['revision'],s['name'])]['counts']['shadow_disagreements']+=1
            return selected
        finally:
            generation['active']-=1
            retired=[g for g in self.retired if not g['active']]
            self.retired=[g for g in self.retired if g['active']]
            for old in retired:
                await asyncio.gather(*(p.aclose() for p in old['providers'].values()),return_exceptions=True)
                for key in list(self.metrics):
                    if key[0]==old['revision']:self.metrics.pop(key,None)
    def model_status(self):
        self.reload()
        rows=[]
        for slot in self.generation['config']['models']:
            metric=self.metrics.get((self.generation['revision'],slot['name']));counts=dict(metric['counts']) if metric else {}
            rows.append({**slot,'status':'disabled' if slot['state']=='disabled' else ('reviewing' if metric else 'configured'),
                         'calls':counts.get('calls',0),'p95_ms':percentile(metric['latency'],.95) if metric else None,
                         'decisions_per_second':counts.get('calls',0)/max(.001,time.monotonic()-metric['started']) if metric else None,
                         'unknown':counts.get('unknown',0),'shadow_disagreements':counts.get('shadow_disagreements',0)})
        return {'revision':self.generation['revision'],'mode':'OBSERVE','models':rows,'rules':self.generation['config']['rules'],
                'reload_error':self.reload_error,'gpu_memory_bytes':None}
    def choice_payload(self,event):
        self.reload()
        core=next(s for s in self.generation['config']['models'] if s['role']=='core')
        return self.generation['providers'][core['name']].transport.choice_payload(event)
    def summary(self):
        core=next(s for s in self.generation['config']['models'] if s['role']=='core')
        return {**self.generation['providers'][core['name']].summary(),'model_slots':self.model_status()}
    async def aclose(self):
        for generation in [self.generation,*self.retired]:
            await asyncio.gather(*(p.aclose() for p in generation['providers'].values()),return_exceptions=True)

        if getattr(self,'prompt_log',None):self.prompt_log.close()
