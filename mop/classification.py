"""Configurable classification over native vLLM-Jev Choice and batch APIs."""
import asyncio
import ipaddress
import json
import math
import re
import time
import uuid
import urllib.parse
import urllib.request
from pathlib import Path
from .core import Verdict, percentile
from collections import deque

DEFAULT_TASK = json.loads(Path(__file__).with_name('default.json').read_text())['classification']


def validate_task(task):
    if not isinstance(task, dict) or set(task) != {'prompt', 'categories'}:
        raise ValueError('classification requires prompt and categories')
    if not isinstance(task['prompt'], str) or not task['prompt'].strip() or len(task['prompt']) > 8192:
        raise ValueError('classification prompt must contain 1..8192 characters')
    categories = task['categories']
    if not isinstance(categories, list) or not 2 <= len(categories) <= 16:
        raise ValueError('classification requires 2..16 categories')
    labels = set()
    for category in categories:
        if not isinstance(category, dict) or set(category) != {'label', 'description'}:
            raise ValueError('each category requires label and description')
        label, description = category['label'], category['description']
        if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', label) or label in labels or label == 'unknown':
            raise ValueError('category labels must be unique identifiers; unknown is reserved for errors')
        if not isinstance(description, str) or not description.strip() or len(description) > 1024:
            raise ValueError('category description must contain 1..1024 characters')
        labels.add(label)
    return task


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Retained for the application proxy; the pooled transport never redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('redirects disabled')


class ClassificationProvider:
    name = 'vllm-jev'

    @property
    def base_url(self):
        return self._base_url

    def __init__(self, base_url, model='mop-open-jev-2b', api_key='', timeout=5,
                 allow_remote=False, cache_policy='native', task=None, function_task=None, artifact_rules=False, input_mode="full"):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            raise ValueError('base URL must be HTTP(S)')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('URL credentials, query and fragment are forbidden')
        try: loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError: loopback = parsed.hostname == 'localhost'
        if not loopback and not allow_remote:
            raise ValueError('non-loopback endpoint requires --allow-remote')
        if not loopback and parsed.scheme != 'https':
            raise ValueError('remote endpoints require HTTPS; use an SSH tunnel for private HTTP')
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError('HTTP timeout must be in (0, 60]')
        if cache_policy not in {'native', 'session', 'isolated', 'off'}:
            raise ValueError('invalid cache policy')
        self._base_url, self.model = base_url.rstrip('/'), model
        self.api_key, self.timeout = api_key, timeout
        self.cache_policy, self.cache_salt = cache_policy, uuid.uuid4().hex
        from .http_pool import HTTPPool
        base=self.base_url[:-3] if self.base_url.endswith('/v1') else self.base_url
        self.http=HTTPPool(base,timeout)
        self.task = validate_task(task if task is not None else DEFAULT_TASK)
        self.instructions = self.task['prompt']
        self.options = tuple(c['label'] + ': ' + c['description'] for c in self.task['categories'])
        self.labels = tuple(c['label'] for c in self.task['categories'])
        self.option_labels = dict(zip(self.options, self.labels))
        if input_mode not in {"full","compact"}: raise ValueError("input_mode must be full or compact")
        self.input_mode=input_mode
        self.artifact_rules=artifact_rules
        if artifact_rules and self.labels!=('normal','suspicious','high_risk'):
            raise ValueError('Artifact rules require normal/suspicious/high_risk labels; disable them for custom labels')
        self.function_task=validate_task(function_task) if function_task is not None else None
        if self.function_task and tuple(c['label'] for c in self.function_task['categories'])!=self.labels:
            raise ValueError('Function policy labels must match the system policy labels and order')
        self.prompt_log = None
        self.rpc_slots = asyncio.Semaphore(2)
        self.native_batch_size = 8
        self.input_token_budget = 3072
        self.rpc_latencies = deque(maxlen=1024)
        self.prefix_costs = {}
        self.stats = {'http_requests': 0, 'decisions_requested': 0, 'cached_tokens': 0, 'prompt_tokens': 0}

    def choice_payload(self, event):
        from .input_projection import project
        payload = project(event,self.input_mode)
        ordered = {'context': payload.pop('context'), **payload}
        task=self.function_task if self.function_task and event.source in {'viztracer','python-runtime'} else self.task
        options=[c['label']+': '+c['description'] for c in task['categories']]
        result = {'state': json.dumps(ordered, ensure_ascii=False, separators=(',', ':')),
                  'question': task['prompt'], 'options': options,
                  'use_prefix_cache': self.cache_policy != 'off'}
        if self.cache_policy == 'session': result['cache_salt'] = self.cache_salt
        return result

    def _decode(self, item, options=None):
        options=tuple(options or self.options)
        option_labels=dict(zip(options,self.labels))
        if not isinstance(item, dict) or item.get('choice') not in options:
            raise ValueError('invalid classification choice')
        probabilities = item.get('probabilities')
        if not isinstance(probabilities, dict) or set(probabilities) != set(options):
            raise ValueError('invalid classification candidates')
        if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in probabilities.values()):
            raise ValueError('invalid classification probabilities')
        if abs(sum(probabilities.values()) - 1) > .02 or probabilities[item['choice']] + 1e-6 < max(probabilities.values()):
            raise ValueError('inconsistent classification result')
        return Verdict(option_labels[item['choice']], 'Classification of supplied evidence; not calibrated safety',
                       self.name, probabilities[item['choice']],
                       probabilities={option_labels[k]: v for k, v in probabilities.items()})

    def prepare_request(self, events):
        if not 1 <= len(events) <= 64: raise ValueError('batch requires 1..64 events')
        requests = [self.choice_payload(event) for event in events]
        suffix = '/plugins/vllm-jev/choice' if len(events) == 1 else '/plugins/vllm-jev/batch'
        body = requests[0] if len(events) == 1 else {'requests': requests}
        return suffix, body

    def request_batch(self, events, prepared=None):
        suffix, body = prepared if prepared is not None else self.prepare_request(events)
        headers = {'Content-Type': 'application/json'}
        if self.api_key: headers['Authorization'] = 'Bearer ' + self.api_key
        started = time.monotonic()
        raw=self.http.post(suffix,json.dumps(body).encode(),headers)
        result = json.loads(raw)
        if not isinstance(result, dict): raise ValueError('invalid model response')
        results = [result] if len(events) == 1 else result.get('results')
        if not isinstance(results, list) or len(results) != len(events): raise ValueError('batch response count mismatch')
        if len(events) > 1 and result.get('decision_count') != len(events): raise ValueError('batch decision count mismatch')
        requests=[body] if len(events)==1 else body['requests']
        verdicts=[self._decode(item,request['options']) for item,request in zip(results,requests)]
        elapsed = (time.monotonic() - started) * 1000
        for verdict in verdicts: verdict.timing.update(rpc_ms=elapsed, batch_size=len(events))
        return verdicts, results

    async def _infer_batch(self, events):
        self.stats['http_requests'] += 1
        self.stats['decisions_requested'] += len(events)
        prepared = self.prepare_request(events)
        body=prepared[1]
        requests=[body] if len(events)==1 else body['requests']
        from .input_projection import serialized
        self.stats['state_bytes_before']=self.stats.get('state_bytes_before',0)+sum(len(serialized(e.payload()).encode()) for e in events)
        self.stats['state_bytes_after']=self.stats.get('state_bytes_after',0)+sum(len(r['state'].encode()) for r in requests)
        self.stats['compacted_events']=self.stats.get('compacted_events',0)+sum(json.loads(r['state']).get('format') in {'mop.function.v1','mop.decision.v2','mop.decision.v3','mop.io.v1'} for r in requests)
        if self.prompt_log:
            self.prompt_log.write_record({'schema_version': 1, 'kind': 'model_request',
                'request_id': uuid.uuid4().hex, 'event_ids': [event.id for event in events],
                'endpoint_path': prepared[0], 'body': prepared[1],
                'note': 'Exact JSON payload before sending; headers and credentials excluded. A recorded attempt does not prove success.'})
        verdicts, raw = await asyncio.to_thread(self.request_batch, events, prepared)
        if verdicts:self.rpc_latencies.append(verdicts[0].timing.get('rpc_ms',0))
        for item in raw:
            for field in ('cached_tokens', 'prompt_tokens'):
                values = item.get(field, [])
                if isinstance(values, list): self.stats[field] += sum(v for v in values if type(v) is int and v >= 0)
        if self.artifact_rules:
            from .artifact_policy import apply
            verdicts=[apply(verdict,event) for verdict,event in zip(verdicts,events)]
        return verdicts

    def bounded_inputs(self,event):
        from .model_budget import tokenizer
        import copy
        tok=tokenizer()
        budget=self.input_token_budget if tok else 3072
        def count(text):
            return len(tok.encode(text,add_special_tokens=False).ids) if tok else len(text.encode())
        original=self.choice_payload(event)
        key=(original['question'],tuple(original['options']),bool(tok))
        if key not in self.prefix_costs:
            if len(self.prefix_costs)>=4:self.prefix_costs.clear()
            self.prefix_costs[key]=256+count(original['question'])+sum(count(s) for s in original['options'])
        overhead=self.prefix_costs[key]
        def cost(value):
            return overhead+count(self.choice_payload(value)['state'])
        if cost(event)<=budget:return [event]
        # Split the exact projected evidence, preserving its source and phase.
        state=original['state']
        output=[];offset=0
        while offset<len(state):
            fragment=copy.deepcopy(event)
            fragment.operation='model_fragment'
            fragment.metadata={'encoding':'json_fragment','original_operation':event.operation,
                'part':64,'parts':64,'content_fragment':''}
            low=0;high=min(len(state)-offset,6000)
            while low<high:
                middle=(low+high+1)//2
                fragment.metadata['content_fragment']=state[offset:offset+middle]
                if cost(fragment)<=budget:low=middle
                else:high=middle-1
            if not low or len(output)>=64:raise ValueError('Input exceeds bounded fragment budget')
            fragment.metadata['content_fragment']=state[offset:offset+low]
            output.append(fragment);offset+=low
        for index,fragment in enumerate(output):fragment.metadata.update(part=index+1,parts=len(output))
        return output

    async def infer_batch(self,events):
        if not 1<=len(events)<=64:raise ValueError('batch requires 1..64 events')
        groups=[];preparation=[]
        for event in events:
            start=time.monotonic()
            try:groups.append(self.bounded_inputs(event))
            except ValueError:groups.append([])
            preparation.append((time.monotonic()-start)*1000)
        flat=[fragment for group in groups for fragment in group]
        self.stats['input_fragments']=self.stats.get('input_fragments',0)+len(flat)
        self.stats['fragmented_inputs']=self.stats.get('fragmented_inputs',0)+sum(len(g)>1 for g in groups)
        async def send(chunk):
            async with self.rpc_slots:
                self.stats['active_rpcs']=self.stats.get('active_rpcs',0)+1
                self.stats['peak_active_rpcs']=max(self.stats.get('peak_active_rpcs',0),self.stats['active_rpcs'])
                try:
                    try:return await self._infer_batch(chunk)
                    except ValueError as error:
                        if len(chunk)<2 or str(error)!='model HTTP status 400':raise
                        self.stats['isolated_rejected_batches']=self.stats.get('isolated_rejected_batches',0)+1
                        isolated=[]
                        for fragment in chunk:
                            try:isolated.extend(await self._infer_batch([fragment]))
                            except Exception as failure:isolated.append(Verdict('unknown','Input failed: '+type(failure).__name__,self.name))
                        return isolated
                finally:self.stats['active_rpcs']-=1
        chunks=[flat[i:i+self.native_batch_size] for i in range(0,len(flat),self.native_batch_size)]
        # Two global RPC slots cover all original batches, not two slots per event.
        replies=await asyncio.gather(*(send(chunk) for chunk in chunks),return_exceptions=True)
        votes=[]
        for chunk,reply in zip(chunks,replies):
            if isinstance(reply,BaseException):
                raise reply
            votes.extend(reply)
        results=[];offset=0
        for index,(event,group) in enumerate(zip(events,groups)):
            if not group:
                results.append(Verdict('unknown','Input exceeds bounded fragment budget',self.name));continue
            current=votes[offset:offset+len(group)];offset+=len(group)
            if len(group)==1:
                current[0].timing['input_prepare_ms']=preparation[index]
                results.extend(current);continue
            import copy
            order={'normal':0,'suspicious':1,'unknown':2,'high_risk':3}
            if self.labels!=('normal','suspicious','high_risk'):
                result=copy.deepcopy(current[0])
                if len({v.category for v in current})>1:result=Verdict('unknown','Fragment categories disagree',self.name)
            else:result=copy.deepcopy(max(current,key=lambda v:order.get(v.category,2)))
            result.reason='Aggregated '+str(len(group))+' evidence fragments'
            result.timing.update(input_fragments=len(group),input_prepare_ms=preparation[index])
            result.model_assessment={'fragments':[{'part':i+1,'category':v.category,'confidence':v.confidence} for i,v in enumerate(current)]}
            if self.artifact_rules:
                from .artifact_policy import apply
                result=apply(result,event)
            results.append(result)
        return results

    async def infer(self, event):
        return (await self.infer_batch([event]))[0]

    async def aclose(self):
        self.http.close()
        if self.prompt_log:
            self.prompt_log.close()
            self.prompt_log = None

    def summary(self):
        return {**self.stats, **self.http.summary(), 'rpc_p95_ms':percentile(self.rpc_latencies,.95), 'native_batch_size':self.native_batch_size, 'input_token_budget':self.input_token_budget, 'input_mode':self.input_mode, 'function_policy_enabled':self.function_task is not None, 'artifact_rules_enabled':self.artifact_rules, 'transport': 'native vLLM-Jev', 'mode': 'classification', 'cache_policy': self.cache_policy}
