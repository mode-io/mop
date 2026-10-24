"""Dependency-free redacted event export for embedded protocol adapters."""
import collections
import json
import os
from pathlib import Path
import re
import time
import uuid

SECRET_KEY=re.compile(r'(?i)(?:password|passwd|secret|api[_-]?key|authorization|cookie|(?:access|refresh|id)?[_-]?token)$')
TEXT_SECRET=re.compile(r'(?i)((?:api[_-]?key|password|passwd|secret|token)\s*[:=]\s*)[^\s,;\"\']+')
AUTH=re.compile(r'(?i)\bBearer\s+[^\s\"\']+')
PREFIX_SECRET=re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})')


def redact(value,depth=0):
    if depth>16:return {'omitted':True,'reason':'nesting_limit'}
    if isinstance(value,dict):return {k:'[REDACTED]' if SECRET_KEY.search(k) else redact(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):return [redact(v,depth+1) for v in value]
    if isinstance(value,str):
        value=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)','[REDACTED PRIVATE KEY]',value,flags=re.S)
        value=AUTH.sub('Bearer [REDACTED]',value)
        value=PREFIX_SECRET.sub('[REDACTED TOKEN]',value)
        return TEXT_SECRET.sub(r'\1[REDACTED]',value)
    return value


class Exporter:
    def __init__(self,config):
        self.config=config;self.uid=int(config['uid']);self.root=Path(config['log_dir'])
        self.stats=collections.Counter();self.collector_id=uuid.uuid4().hex

    def emit(self,pid,kind,evidence,**flags):
        clean=redact(evidence)
        serialized=json.dumps(clean,ensure_ascii=True,separators=(',',':'))
        if len(serialized)>3500:
            identifier=uuid.uuid4().hex
            # Valid JSON envelopes; only the explicitly named fragment is partial JSON.
            # Redact the complete object before slicing, including cross-boundary secrets.
            request=clean.pop('original_request',None) if isinstance(clean,dict) else None
            context=request
            context_flags={}
            if request is not None and len(json.dumps(request,ensure_ascii=True))>1400:
                context={k:v for k,v in request.items() if k!='body'}
                context['body_omitted']=True
                context_flags['request_context_partial']=True
                if len(json.dumps(context,ensure_ascii=True))>1400:context={'context_omitted':True}
            serialized=json.dumps(clean,ensure_ascii=True,separators=(',',':'))
            fragments=[serialized[i:i+900] for i in range(0,len(serialized),900)]
            for index,fragment in enumerate(fragments[:512]):
                item={'content_id':identifier,'part':index+1,'parts':len(fragments),
                      'encoding':'json_fragment','content_fragment':fragment}
                if context is not None:item['original_request']=context
                self._write(pid,kind,item,{**flags,**context_flags,'fragmented':True,
                    'parts_omitted':max(0,len(fragments)-512)})
            self.stats['content_fragments']+=min(len(fragments),512)
            if len(fragments)>512:self.stats['content_parts_omitted']+=len(fragments)-512
            return
        self._write(pid,kind,clean,flags)

    def _write(self,pid,kind,clean,flags):
        self.stats['sequence']+=1
        event={'operation':'captured_io','source':self.config.get('source','system-content'),'metadata':{
            'collector_id':self.collector_id,'sequence':self.stats['sequence'],
            'uid':self.uid,'observed_pid':pid,'kind':kind,'captured_at':time.time(),
            'evidence':clean,'capture_status':{'redaction':'best_effort',**flags}}}
        path=self.root/'events.jsonl'
        if path.exists() and path.stat().st_size>4*1024*1024:
            (self.root/'events.jsonl.3').unlink(missing_ok=True)
            for index in (2,1):
                old=self.root/('events.jsonl.'+str(index))
                if old.exists():old.replace(self.root/('events.jsonl.'+str(index+1)))
            path.replace(self.root/'events.jsonl.1')
        fd=os.open(path,os.O_APPEND|os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as stream:stream.write(json.dumps(event,ensure_ascii=True)+'\n')
        self.stats[kind]+=1

