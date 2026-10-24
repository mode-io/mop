#!/usr/bin/env python3
"""Privileged bounded collectors. Raw bytes stay in pipes/memory, never journals."""
import argparse
import base64
import collections
import json
import logging.handlers
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import urllib.parse
import uuid
import zlib

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


CAPTURE_BYTES=3072

def stdout_program(uid):
    program = r'''tracepoint:syscalls:sys_enter_write
/uid == UID && args->count > 0 && (uint64)args->buf < 0x7fffffffd000 && (args->fd == 1 || args->fd == 2)/
{
  $second = nsecs / 1000000000;
  if (@second[pid] != $second) { @second[pid] = $second; @rate[pid] = 0; }
  if (@allsecond != $second) { @allsecond=$second; @allrate=0; }
  @rate[pid]++; @allrate++;
  if (@rate[pid] <= 200 && @allrate <= 1000) {
    @ts[tid] = nsecs; @wc[tid]=args->count; @wb[tid]=(uint64)args->buf;
    $n=(uint64)@wc[tid]; $b=(uint64)@wb[tid];
    printf("MOPW %d %d %llu %d %llu %r\n", pid, tid, @ts[tid], args->fd, $n,
           buf((uint8 *)$b, $n > 192 ? 192 : $n));
    EXTRA_STDOUT
  } else { @dropped++; }
}
tracepoint:syscalls:sys_exit_write /uid == UID && @ts[tid]/
{ printf("MOPR %d %d %llu %d\n",pid,tid,@ts[tid],args->ret); delete(@ts[tid]); delete(@wc[tid]); delete(@wb[tid]); }
tracepoint:sched:sched_process_exit /uid == UID/ { delete(@ts[tid]); delete(@wc[tid]); delete(@wb[tid]); }
interval:s:1 { if (@dropped) { printf("MOPD %d\n",@dropped); @dropped=0; } }
'''.replace('UID',str(uid))
    extra='\n'.join('''if ($n > OFFSET) {
       printf("MOPX %d %d %llu %d %r\\n",pid,tid,@ts[tid],OFFSET,
         buf((uint8 *)($b+OFFSET),$n-OFFSET > 192 ? 192 : $n-OFFSET));
    }'''.replace('OFFSET',str(offset)) for offset in range(192,CAPTURE_BYTES,192))
    return program.replace('EXTRA_STDOUT',extra)


def tls_ex_program(uid, library, family="openssl", extended=True):
    if not re.fullmatch(r'/[A-Za-z0-9_./+-]+',library):raise ValueError('Unsupported library path')
    blocks=[]
    functions=[('r0','SSL_read','READ',False),('w0','SSL_write','WRITE',False)]
    close='SSL_free'
    if family=='openssl' and extended:functions=[('rd','SSL_read_ex','READ',True),('wr','SSL_write_ex','WRITE',True)]+functions
    elif family=='gnutls':functions=[('r0','gnutls_record_recv','READ',False),('w0','gnutls_record_send','WRITE',False)];close='gnutls_deinit'
    elif family=='nspr':functions=[('r0','PR_Read','READ',False),('w0','PR_Write','WRITE',False)];close='PR_Close'
    elif family!='openssl':raise ValueError('Unsupported TLS probe family')
    for short,func,direction,extended in functions:
        chunks='\n'.join('''if ($n > OFFSET) {
          printf("MOPT %d %d %llu %llu DIRECTION %llu %d %r\\n",pid,tid,@TAG_ts[tid],@TAG_ssl[tid],$n,OFFSET,
            buf((uint8 *)(@TAG_buf[tid]+OFFSET), $n-OFFSET > 192 ? 192 : $n-OFFSET));
        }'''.replace('OFFSET',str(offset)) for offset in range(0,CAPTURE_BYTES,192))
        blocks.append('''
uprobe:LIBRARY:FUNCTION /uid == UID && arg1 > 0 && arg1 < 0x7fffffffd000 LENGTH_CHECK/
{
  $second=nsecs / 1000000000;
  if (@tls_second != $second) { @tls_second=$second; @tls_rate=0; }
  @tls_rate++;
  if (@tls_rate <= 200 && !@tls_busy[tid]) { @tls_busy[tid]=1; @TAG_ts[tid]=nsecs; @TAG_buf[tid]=arg1; @TAG_len[tid]=arg3; @TAG_ssl[tid]=arg0; }
  else if (!@tls_busy[tid]) { @dropped++; }
}
uretprobe:LIBRARY:FUNCTION /uid == UID && @TAG_ts[tid]/
{
  if (RETURN_CHECK) {
    $n = (int64)(LENGTH_VALUE);
    if ($n > CAPTURE_BYTES) { printf("MOPG %d %llu %llu\\n",pid,@TAG_ssl[tid],$n); }
    else {
      CHUNKS
    }
  }
  delete(@TAG_ts[tid]); delete(@TAG_buf[tid]); delete(@TAG_len[tid]); delete(@TAG_ssl[tid]); delete(@tls_busy[tid]);
}
'''.replace('CHUNKS',chunks).replace('LIBRARY',library).replace('FUNCTION',func).replace('DIRECTION',direction).replace('UID',str(uid))
            .replace('LENGTH_CHECK','&& arg3 > 0 && arg3 < 0x7ffffffffff8' if extended else '')
            .replace('RETURN_CHECK','retval == 1' if extended else 'retval > 0 && retval <= 0x7fffffff')
            .replace('LENGTH_VALUE','*(uint64 *)@TAG_len[tid]' if extended else 'retval').replace('TAG',short).replace('CAPTURE_BYTES',str(CAPTURE_BYTES)))
    cleanup=' '.join('delete(@%s_%s[tid]);' % (tag,key) for tag in [item[0] for item in functions] for key in ('ts','buf','len','ssl'))
    blocks.append('tracepoint:sched:sched_process_exit /uid == %d/ { delete(@tls_busy[tid]); %s }' % (uid,cleanup))
    blocks.append('uprobe:%s:%s /uid == %d/ { printf("MOPC %%d %%llu\\n",pid,arg0); }' % (library,close,uid))
    return '\n'.join(blocks)


def decode_buffer(text, expected):
    decoded=re.sub(r'\\x([0-9a-fA-F]{2})',lambda m:chr(int(m.group(1),16)) if int(m.group(1),16)<32 or int(m.group(1),16)>126 else m.group(0),text).encode('latin1')
    if len(decoded)!=expected:raise ValueError('Ambiguous bpftrace buffer encoding')
    return decoded


class HTTPStream:
    """Bounded HTTP/1 framing; no guessing after malformed or missing bytes."""
    LIMIT=262144
    def __init__(self, agent, connection, direction):
        self.agent=agent;self.connection=connection;self.direction=direction
        self.buffer=b'';self.stage='headers';self.message=None;self.remaining=0
        self.body=bytearray();self.sse=b'';self.event_lines=[];self.event_index=0
        self.total=0;self.last=time.monotonic()

    def fail(self, reason):
        self.agent.invalidate(self.connection[0],self.connection[2],reason)
        raise ValueError(reason)

    def feed(self, data):
        self.last=time.monotonic();self.buffer+=data
        if len(self.buffer)>self.LIMIT+16384:self.fail('http_buffer_limit')
        while True:
            if self.stage=='headers':
                end=self.buffer.find(b'\r\n\r\n')
                if end<0:
                    if len(self.buffer)>16384:self.fail('http_header_limit')
                    return
                raw=self.buffer[:end];self.buffer=self.buffer[end+4:]
                lines=raw.decode('latin1').split('\r\n')
                req=re.fullmatch(r'([A-Z]+) (\S+) HTTP/1\.[01]',lines[0])
                res=re.fullmatch(r'HTTP/1\.[01] (\d{3})(?: .*)?',lines[0])
                if not req and not res:self.fail('unsupported_protocol')
                headers={}
                for line in lines[1:]:
                    if ':' not in line or line[:1] in (' ','\t'):self.fail('invalid_headers')
                    name,value=line.split(':',1);name=name.lower();value=value.strip()
                    if name in headers and name in ('content-length','transfer-encoding'):self.fail('ambiguous_framing')
                    headers[name]=value
                if 'transfer-encoding' in headers and 'content-length' in headers:self.fail('ambiguous_framing')
                encoding=headers.get('content-encoding','identity').lower()
                if encoding not in ('identity','gzip','deflate'):self.fail('unsupported_encoding')
                self.decoder=zlib.decompressobj(31 if encoding=='gzip' else zlib.MAX_WBITS) if encoding!='identity' else None
                self.wire_total=0
                queue=self.agent.requests.setdefault(self.connection,collections.deque())
                if req:
                    method,target=req.groups()
                    self.message={'method':method,'path':urllib.parse.urlsplit(target).path,'host':headers.get('host','')}
                    self.kind='http_request';self.request=None
                else:
                    status=int(res.group(1));self.kind='http_response'
                    self.message={'status':status,'content_type':headers.get('content-type','')}
                    self.request=queue[0] if queue and queue[0]['direction']!=self.direction else None
                    if status==101:self.fail('protocol_upgrade')
                    if self.request and self.request['evidence'].get('method')=='CONNECT':self.fail('protocol_upgrade')
                self.is_sse=self.kind=='http_response' and headers.get('content-type','').split(';')[0].strip().lower()=='text/event-stream'
                self.body=bytearray();self.sse=b'';self.event_lines=[];self.event_index=0;self.total=0
                status=self.message.get('status',0)
                no_body=res and (100<=status<200 or status in (204,304) or (self.request and self.request['evidence'].get('method')=='HEAD'))
                transfer=headers.get('transfer-encoding','').lower()
                if no_body:self.finish();continue
                if transfer:
                    if transfer!='chunked':self.fail('unsupported_encoding')
                    self.stage='size'
                elif 'content-length' in headers:
                    value=headers['content-length']
                    if not re.fullmatch(r'[0-9]+',value):self.fail('invalid_content_length')
                    self.remaining=int(value)
                    if self.remaining>self.LIMIT:self.fail('http_body_limit')
                    self.stage='fixed'
                elif req:self.finish();continue
                else:self.fail('unknown_body_length')
            elif self.stage=='fixed':
                take=min(len(self.buffer),self.remaining)
                self.accept(self.buffer[:take]);self.buffer=self.buffer[take:];self.remaining-=take
                if self.remaining:return
                self.finish()
            elif self.stage=='size':
                end=self.buffer.find(b'\r\n')
                if end<0:
                    if len(self.buffer)>1024:self.fail('chunk_size_limit')
                    return
                size=self.buffer[:end].split(b';',1)[0]
                if not re.fullmatch(b'[0-9a-fA-F]{1,8}',size):self.fail('invalid_chunk_size')
                self.remaining=int(size,16);self.buffer=self.buffer[end+2:]
                if self.remaining>self.LIMIT:self.fail('chunk_size_limit')
                self.stage='chunk' if self.remaining else 'trailers'
            elif self.stage=='chunk':
                take=min(len(self.buffer),self.remaining)
                self.accept(self.buffer[:take]);self.buffer=self.buffer[take:];self.remaining-=take
                if self.remaining:return
                self.stage='chunk_end'
            elif self.stage=='chunk_end':
                if len(self.buffer)<2:return
                if self.buffer[:2]!=b'\r\n':self.fail('invalid_chunk_end')
                self.buffer=self.buffer[2:];self.stage='size'
            elif self.stage=='trailers':
                end=self.buffer.find(b'\r\n')
                if end<0:
                    if len(self.buffer)>16384:self.fail('trailer_limit')
                    return
                line=self.buffer[:end];self.buffer=self.buffer[end+2:]
                if not line:self.finish()
                elif ':' not in line.decode('latin1'):self.fail('invalid_trailer')

    def accept(self,data):
        self.wire_total+=len(data)
        if self.wire_total>self.LIMIT:self.fail('http_wire_limit')
        if self.decoder:
            try:data=self.decoder.decompress(data,self.LIMIT-self.total+1)
            except zlib.error:self.fail('invalid_compression')
            if self.decoder.unconsumed_tail:self.fail('decompression_limit')
        self.total+=len(data)
        if self.total>self.LIMIT:self.fail('http_body_limit')
        if not self.is_sse:self.body.extend(data);return
        self.sse+=data
        # Consume CR, LF and CRLF, retaining a trailing CR until the next read.
        while True:
            match=re.search(b'\r\n|\r|\n',self.sse)
            if not match or (match.group()==b'\r' and match.end()==len(self.sse)):break
            line=self.sse[:match.start()];self.sse=self.sse[match.end():]
            if line:self.event_lines.append(line)
            else:
                values=[];event_type=None
                for item in self.event_lines:
                    name,sep,value=item.partition(b':')
                    if value.startswith(b' '):value=value[1:]
                    if name==b'data':values.append(value)
                    elif name==b'event':event_type=value.decode('utf-8','replace')
                self.event_lines=[]
                if values:
                    self.event_index+=1
                    evidence={**self.message,'event_index':self.event_index,'body':self.decode(b'\n'.join(values))}
                    if event_type:evidence['event_type']=event_type
                    self.publish('http_response_event',evidence,complete=False,event_complete=True)
        if len(self.sse)+sum(map(len,self.event_lines))>65536:self.fail('sse_event_limit')

    @staticmethod
    def decode(data):
        text=data.decode('utf-8','replace')
        if b'\x00' in data:raise ValueError('binary_body')
        try:return json.loads(text) if text else None
        except (ValueError,RecursionError):return text

    def publish(self,kind,evidence,**flags):
        if self.kind=='http_response':
            if self.request:
                evidence['request_id']=self.request['id']
                evidence['original_request']=self.request['evidence']
            flags['request_context_captured']=bool(self.request)
            if self.request and self.request['evidence'].get('body_omitted'):flags['request_context_partial']=True
        self.agent.emit(self.connection[0],kind,evidence,protocol='http1',**flags)

    def finish(self):
        if self.decoder and not self.decoder.eof:self.fail('incomplete_compression')
        if self.is_sse:
            self.publish('http_response_end',{**self.message,'events':self.event_index},complete=True,
                         trailing_event_incomplete=bool(self.sse or self.event_lines))
        else:
            evidence={**self.message,'body':self.decode(bytes(self.body))}
            if self.kind=='http_request':
                queue=self.agent.requests[self.connection]
                if len(queue)>=16:self.fail('request_queue_limit')
                identifier=uuid.uuid4().hex
                # Keep redacted request data, never authorization headers.
                context=redact(evidence)
                if len(json.dumps(context,ensure_ascii=True))>16384:
                    context={k:v for k,v in context.items() if k!='body'}
                    context['body_omitted']=True
                queue.append({'id':identifier,'direction':self.direction,'evidence':context})
                evidence['request_id']=identifier
            self.publish(self.kind,evidence,complete=True)
        if self.kind=='http_response' and not 100<=self.message['status']<200 and self.request:
            self.agent.requests[self.connection].popleft()
        self.stage='headers';self.message=None;self.body=bytearray();self.sse=b'';self.event_lines=[]


class Agent:
    def __init__(self, config):
        self.config=config;self.uid=int(config['uid']);self.root=Path(config['log_dir'])
        if self.uid<=0:raise ValueError('A non-root target UID is required')
        self.stop=threading.Event();self.lock=threading.RLock();self.stats=collections.Counter()
        self.pending={};self.lines={};self.http={};self.requests={};self.exclusions={};self.private=set();self.tls_parts={}
        self.children=[];self.collector_id=uuid.uuid4().hex;self.diagnostics=collections.deque(maxlen=6);self.http_disabled=set();self.output_gaps=set();self.lifetimes={};self.adapters={};self.discovery_errors=0;self.uncovered_targets=[];self.h2_sessions={};self.h2_module=None;self.opaque={}
        self.writer=logging.handlers.RotatingFileHandler(self.root/'events.jsonl',maxBytes=4*1024*1024,backupCount=3)
        self.writer.setFormatter(__import__('logging').Formatter('%(message)s'))
        self.logger=__import__('logging').getLogger('content');self.logger.setLevel(20);self.logger.addHandler(self.writer);self.logger.propagate=False

    def excluded(self,pid):
        now=time.monotonic();cached=self.exclusions.get(pid)
        if cached and now-cached[0]<1:return cached[1]
        current=pid;excluded=False
        for _ in range(6):
            if current==os.getpid():excluded=True;break
            try:
                path=Path('/proc')/str(current)
                with (path/'cmdline').open('rb') as stream:argv=stream.read(16384).split(b'\0')
                if (argv and argv[0].endswith(b'/mitmproxy-12.2.3/mitmdump')) or any(a==b'-m' and i+1<len(argv) and argv[i+1]==b'mop' for i,a in enumerate(argv)) or b'mop-open-jev-2b' in argv:
                    excluded=True;break
                stat=(path/'stat').read_text();current=int(stat[stat.rindex(')')+2:].split()[1])
                if current<=1:break
            except (OSError,ValueError,IndexError):break
        if len(self.exclusions)>2048:self.exclusions.clear()
        self.exclusions[pid]=(now,excluded);return excluded

    def emit(self,pid,kind,evidence,**flags):
        if self.excluded(pid):self.stats['pipeline_excluded']+=1;return
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
            'evidence':clean,'capture_status':{'redaction':'best_effort','adapter_family':getattr(self,'current_adapter','unknown'),**flags}}}
        self.logger.info(json.dumps(event,ensure_ascii=True));self.stats[kind]+=1

    def lifetime(self,pid,fallback):
        try:
            raw=(Path('/proc')/str(pid)/'stat').read_text()
            value=int(raw[raw.rindex(')')+2:].split()[19])
            if len(self.lifetimes)>4096:self.lifetimes.clear()
            self.lifetimes[pid]=(value,time.monotonic())
            return value
        except (OSError,ValueError,IndexError):
            cached=self.lifetimes.get(pid)
            return cached[0] if cached and time.monotonic()-cached[1]<30 else fallback

    def stdio(self,line):
        loss=re.search(r'(?i)\blost(?:_samples|samples|_events)?[=: ]+(\d+)',line)
        if loss:line='MOPL '+loss.group(1)
        if line.startswith('MOPC '):
            _,pid,connection=line.split();pid=int(pid);connection=int(connection)
            for key,parser in list(self.http.items()):
                if key[0]==pid and key[2]==connection:
                    if parser.stage!='headers' or parser.buffer:
                        self.emit(pid,'capture_gap',{'component':'http','reason':'connection_closed_before_message_complete'},complete=False)
                    self.http.pop(key,None)
            for key in list(self.requests):
                if key[0]==pid and key[2]==connection:self.requests.pop(key,None)
            for key in list(self.h2_sessions):
                if key[0]==pid and key[2]==connection:self.h2_sessions.pop(key,None)
            self.opaque={key:stamp for key,stamp in self.opaque.items() if not (key[0]==pid and key[2]==connection)}
            self.http_disabled.discard((pid,connection))
            return
        if line.startswith('MOPG '):
            _,pid,connection,total=line.split();pid=int(pid);connection=int(connection)
            self.invalidate(pid,connection,'tls_call_limit')
            return
        if line.startswith('MOPT '):
            fields=line.split(' ',8)
            pid,tid,stamp,connection=map(int,fields[1:5]);direction=fields[5];total,offset=map(int,fields[6:8])
            if total>CAPTURE_BYTES:
                self.stats['tls_ex_truncated']+=1
                if len(self.http_disabled)<192:self.http_disabled.add((pid,connection))
                else:self.stats['http_gap_overflow']+=1
                return
            if len(self.tls_parts)>=128:self.tls_parts.clear();self.stats['tls_ex_overflow']+=1
            key=(pid,tid,stamp,direction)
            parts=self.tls_parts.setdefault(key,{'total':total,'data':{},'at':time.monotonic(),'connection':connection})
            try:parts['data'][offset]=decode_buffer(fields[8],min(192,total-offset))
            except ValueError:
                if len(self.http_disabled)<192:self.http_disabled.add((pid,connection))
                else:self.stats['http_gap_overflow']+=1
                raise
            if sum(map(len,parts['data'].values()))==total:
                data=b''.join(parts['data'][i] for i in range(0,total,192))
                self.tls_parts.pop(key,None)
                self.stats['tls_ex_records']+=1
                self.tls_payload({'pid':pid,'fd':connection,'tuple':'ssl-object','direction':direction},data)
            return
        if line.startswith('MOP_READY'):self.stats['stdout_ready']=1;return
        if line.startswith(('MOPD ','MOPL ')):
            self.stats['perf_loss_gaps' if line.startswith('MOPL ') else 'rate_dropped']+=int(line.split()[1])
            for pid,connection in {(key[0],key[2]) for key in list(self.http)+list(self.h2_sessions)}:self.invalidate(pid,connection,'collector_transport_loss')
            self.output_gaps.update(self.lines)
            if len(self.output_gaps)>1024:self.stats['output_continuity_unknown']=1;self.output_gaps.clear()
            self.lines.clear();self.pending.clear();self.tls_parts.clear()
            return
        if not line.startswith(('MOPW ','MOPR ','MOPX ')):return
        fields=line.split(' ',6);pid,tid,stamp=map(int,fields[1:4]);key=(pid,tid,stamp)
        if len(self.pending)>=512:self.pending.clear();self.stats['pending_overflow']+=1
        item=self.pending.setdefault(key,{'at':time.monotonic()})
        if fields[0]=='MOPW':
            expected=min(int(fields[5]),192)
            encoded=fields[6]
            try:decoded=decode_buffer(encoded,expected)
            except ValueError:
                self.stats['ambiguous_output_encoding']+=1;self.pending.pop(key,None);return
            item.update(fd=int(fields[4]),requested=int(fields[5]),data=decoded)
            self.stats['stdout_ready']=1
        elif fields[0]=='MOPX':
            fields=line.split(' ',5);offset=int(fields[4])
            item.setdefault('chunks',{})[offset]=fields[5]
        else:item['result']=int(fields[4])
        if 'data' not in item or 'result' not in item:return
        needed=min(item['requested'],CAPTURE_BYTES)
        if needed>192:
            offsets=range(192,needed,192)
            if not all(offset in item.get('chunks',{}) for offset in offsets):return
            item['data']=item['data'][:192]+b''.join(decode_buffer(item['chunks'][offset],min(192,needed-offset)) for offset in offsets)
        self.pending.pop(key,None)
        if self.excluded(pid):self.stats['pipeline_excluded']+=1;return
        result=item['result'];data=item['data'][:max(0,result)]
        if result<=0:return
        if result>len(data):
            self.stats['truncated_writes']+=1
            self.emit(pid,'stdio',{'fd':item['fd'],'written_bytes':result,'captured_bytes':len(data)},truncated=True)
            for old in list(self.lines):
                if old[0]==pid and old[2]==item['fd']:self.output_gaps.add(old);self.lines.pop(old,None)
            return
        k=(pid,self.lifetime(pid,0),item['fd']);pending=self.lines.get(k,b'')+data
        if len(pending)>262144 or b'\x00' in pending:
            self.output_gaps.add(k);self.lines.pop(k,None);self.stats['omitted_output']+=1;return
        complete,sep,tail=pending.rpartition(b'\n')
        if sep:
            safe=[]
            for line in (complete+sep).splitlines(keepends=True):
                if k in self.private:
                    if b'-----END ' in line and b'PRIVATE KEY-----' in line:self.private.discard(k)
                elif b'-----BEGIN ' in line and b'PRIVATE KEY-----' in line:
                    if b'-----END ' not in line:self.private.add(k)
                    safe.append(b'[REDACTED PRIVATE KEY]\n')
                else:safe.append(line)
            if len(self.private)>512:self.stats['privacy_overflow']+=1;return
            if safe and not self.stats['privacy_overflow']:
                self.emit(pid,'stdio',{'stream':'stdout' if item['fd']==1 else 'stderr','text':b''.join(safe).decode('utf-8','replace')},truncated=False,ordering='arrival',preceding_bytes_missing=(k in self.output_gaps or bool(self.stats['output_continuity_unknown'])))
            self.output_gaps.discard(k)
        if len(self.lines)>512:self.lines.clear();self.stats['line_overflow']+=1
        if tail:self.lines[k]=tail
        else:self.lines.pop(k,None)

    def invalidate(self,pid,connection,reason):
        self.stats[reason+'_gaps']+=1
        if len(self.http_disabled)>=1024:
            self.stats['http_gap_overflow']+=1
        else:self.http_disabled.add((pid,connection))
        for key in list(self.http):
            if key[0]==pid and key[2]==connection:self.http.pop(key,None)
        for key in list(self.h2_sessions):
            if key[0]==pid and key[2]==connection:self.h2_sessions.pop(key,None)
        for key in list(self.requests):
            if key[0]==pid and key[2]==connection:self.requests.pop(key,None)
        self.emit(pid,'capture_gap',{'component':'http','reason':reason},complete=False)

    def tls_payload(self,record,data):
        pid=record['pid'];connection=record['fd']
        if self.stats['http_gap_overflow'] or (pid,connection) in self.http_disabled:return
        if self.excluded(pid):self.stats['pipeline_excluded']+=1;return
        base=(pid,self.lifetime(pid,0),connection,record['tuple'])
        key=base+(record['direction'],)
        starts=(b'GET ',b'POST ',b'PUT ',b'PATCH ',b'DELETE ',b'HEAD ',b'OPTIONS ',b'CONNECT ',b'TRACE ',b'HTTP/1.',b'PRI * HTTP/2.0')
        maybe_http=any(data.startswith(prefix) or prefix.startswith(data) for prefix in starts)
        maybe_h2=bool(data and data[0]==0)
        if base in self.opaque or (key not in self.http and base not in self.h2_sessions and not maybe_http and not maybe_h2 and (len(data)>=8 or b'\n' in data)):
            if len(self.opaque)>=128 and base not in self.opaque:self.invalidate(pid,connection,'opaque_connection_limit');return
            self.opaque[base]=time.monotonic()
            try:
                text=data.decode('utf-8')
                if '\x00' in text:raise ValueError('binary')
                payload={'text':text}
            except (UnicodeDecodeError,ValueError):payload={'encoding':'base64','data':base64.b64encode(data).decode()}
            self.emit(pid,'transport_payload',{'direction':record['direction'],'captured_bytes':len(data),**payload},
                      complete=False,protocol_decoded=False,transport='user_space_plaintext')
            return
        try:
            if base in self.h2_sessions:
                self.h2_sessions[base].feed(record['direction'],data);return
            buffered=self.http[key].buffer if key in self.http else b''
            combined=buffered+data
            if combined.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
                if self.h2_module is None:
                    import importlib.util
                    spec=importlib.util.spec_from_file_location('capture_http2',Path(__file__).with_name('capture_http2.py'))
                    self.h2_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.h2_module)
                if len(self.h2_sessions)>=64:self.invalidate(pid,connection,'http2_connection_limit');return
                session=self.h2_module.Session(self,base,record['direction']);self.h2_sessions[base]=session
                session.feed(record['direction'],combined)
                for old,parser in list(self.http.items()):
                    if old[:-1]==base:
                        if old!=key:session.feed(old[-1],parser.buffer)
                        self.http.pop(old,None)
                return
        except (ImportError,ValueError,KeyError,OverflowError):
            self.invalidate(pid,connection,'http2_decode_error');return
        if key not in self.http:
            if len(self.http)>=128:
                self.invalidate(pid,connection,'http_connection_limit');return
            self.http[key]=HTTPStream(self,base,record['direction'])
        try:self.http[key].feed(data)
        except (ValueError,RecursionError,OverflowError):
            if (pid,connection) not in self.http_disabled:self.invalidate(pid,connection,'http_parse_error')

    def read_tls(self,proc):
        header=re.compile(r'^\[[^\]\n]+\] PID:(\d+) TID:(\d+) Comm:.*? FD:(\d+)(?: Tuple:(.*?))? (READ|WRITE) \((\d+) bytes, hex\):$')
        record=None;data=bytearray()
        for raw in iter(proc.stdout.readline,b''):
            if len(raw)>8192:self.stats['tls_parse_errors']+=1;continue
            line=raw.decode('ascii','replace').rstrip('\n');match=header.match(line)
            try:
                with self.lock:
                    if match:
                        p,t,f,connection,d,n=match.groups()
                        record={'pid':int(p),'fd':int(f),'tuple':connection or '', 'direction':d,'length':int(n)};data=bytearray()
                        if not 0<record['length']<=16384:record=None;self.stats['tls_oversized']+=1
                    elif record and re.match(r'^[0-9A-F]{4}  ',line):
                        data.extend(bytes.fromhex(line[4:].split('    ',1)[0]))
                        if len(data)>=record['length']:
                            self.tls_payload(record,bytes(data[:record['length']]));record=None
            except (ValueError,IndexError,RecursionError):self.stats['tls_parse_errors']+=1;record=None

    def drain_errors(self,proc,name):
        for line in iter(proc.stderr.readline,b''):
            with self.lock:
                self.stats[name+'_diagnostics']+=1
                message=re.sub(r'\x1b\[[0-9;]*m','',line.decode('utf-8','replace'))
                if re.search(r'(?i)\blost(?:_samples|samples|_events)?[=: ]+\d+',message):self.stdio(message)
                self.diagnostics.append(name+': '+redact(line.decode('utf-8','replace'))[:192])

    def read_gotls(self,proc,adapter):
        pattern=re.compile(r'PID:(\d+), TID:(\d+), Comm:.*?, FD:(\d+),(?: Tuple:(.*?),)? Type:(READ|WRITE), Len:(\d+)')
        record=None
        for raw in iter(proc.stdout.readline,b''):
            if len(raw)>65536:self.stats['gotls_oversized_gaps']+=1;record=None;continue
            line=raw.decode('ascii','replace').strip();match=pattern.search(line)
            try:
                if match:
                    pid,tid,fd,connection,direction,length=match.groups()
                    record={'pid':int(pid),'fd':int(fd),'tuple':connection or 'gotls','direction':direction,'length':int(length)}
                    if not 0<record['length']<=16384:record=None
                elif record and re.fullmatch('[0-9a-fA-F]+',line):
                    data=bytes.fromhex(line)
                    if len(data)!=record['length']:raise ValueError('Incomplete Go TLS event')
                    with self.lock:
                        self.current_adapter='gotls'
                        self.tls_payload(record,data)
                        self.adapters[adapter]['records']=self.adapters[adapter].get('records',0)+1
                    record=None
            except (ValueError,KeyError):self.stats['gotls_parse_gaps']+=1;record=None
        with self.lock:
            if adapter in self.adapters:self.adapters[adapter]['status']='exited'

    def discover_adapters(self,env):
        import importlib.util
        module_path=Path(__file__).with_name('capture_discovery.py')
        spec=importlib.util.spec_from_file_location('capture_discovery',module_path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.ON_CHILD=lambda pid:self.exclusions.update({pid:(time.monotonic()+30,True)})
        primary=Path(self.config['libssl']).resolve()
        while not self.stop.is_set():
            try:
                targets=module.discover(self.uid)
                self.uncovered_targets=[{'path':t['path'],'family':t['family']} for t in targets[8:16]]
                targets=targets[:8]
                active={item['path'] for item in targets}
                with self.lock:
                    self.children=[c for i,c in enumerate(self.children) if i==0 or c.poll() is None]
                    for old,item in list(self.adapters.items()):
                        if old not in active:
                            for child in self.children[1:]:
                                if child.pid==item.get('pid') and child.poll() is None:child.send_signal(signal.SIGINT)
                            self.adapters.pop(old,None)
                for target in targets:
                    if self.stop.is_set():break
                    if Path(target['path'])==primary:continue
                    key=target['path']
                    with self.lock:
                        if key in self.adapters:continue
                        if len(self.adapters)>=8:self.stats['adapter_limit_gaps']+=1;break
                        self.adapters[key]={'family':target['family'],'status':'starting'}
                    if target['family']=='gotls':
                        child=subprocess.Popen([self.config['ecapture'],'gotls','--elfpath',key,'--uid',str(self.uid),
                            '--mapsize','16','--hex','--eventaddr','stdout','--logaddr','/dev/null','--listen='],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
                        with self.lock:self.children.append(child);self.adapters[key].update(status='probe_started',pid=child.pid)
                        threading.Thread(target=self.read_gotls,args=(child,key),daemon=True).start()
                        threading.Thread(target=self.drain_errors,args=(child,'gotls'),daemon=True).start()
                        continue
                    path=Path('/run')/('mop-content-'+str(self.uid))/('tls-'+uuid.uuid4().hex[:12]+'.bt')
                    source=tls_ex_program(self.uid,key,target['family'],target['extended'])
                    source+='\ninterval:s:1 { if (@dropped) { printf("MOPD %d\\n",@dropped); @dropped=0; } }'
                    path.write_text(source)
                    child=subprocess.Popen(['/usr/bin/stdbuf','-oL','/usr/bin/bpftrace','-q',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
                    with self.lock:
                        self.children.append(child)
                        self.adapters[key].update(status='probe_started',pid=child.pid)
                    def read(proc=child,adapter=key):
                        for raw in iter(proc.stdout.readline,b''):
                            try:
                                with self.lock:
                                    self.current_adapter=self.adapters.get(adapter,{}).get('family','unknown')
                                    self.stdio(raw.decode('ascii','replace').rstrip('\n'))
                                    self.adapters[adapter]['records']=self.adapters[adapter].get('records',0)+1
                            except (ValueError,IndexError,KeyError,RecursionError):self.stats['adapter_parse_errors']+=1
                        with self.lock:
                            if adapter in self.adapters:self.adapters[adapter]['status']='exited'
                    threading.Thread(target=read,daemon=True).start()
                    threading.Thread(target=self.drain_errors,args=(child,'adapter'),daemon=True).start()
                    if self.stop.wait(2):break
            except Exception:
                with self.lock:self.discovery_errors+=1
            self.stop.wait(30)

    def start(self):
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','BPFTRACE_PERF_RB_PAGES':'16','BPFTRACE_STRLEN':'192',
             'BPFTRACE_MAP_KEYS_MAX':'4096','GOMAXPROCS':'2'}
        program=Path('/run')/('mop-content-'+str(self.uid))/'stdout.bt'
        source=stdout_program(self.uid)
        if self.config.get('tls_ex_enabled'):source+='\n'+tls_ex_program(self.uid,self.config['libssl'])
        program.write_text(source)
        std=subprocess.Popen(['/usr/bin/stdbuf','-oL','/usr/bin/bpftrace','-q',str(program)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        self.children.append(std)
        def read_stdio():
            for raw in iter(std.stdout.readline,b''):
                try:
                    with self.lock:
                        self.current_adapter='openssl'
                        self.stdio(raw.decode('ascii','replace').rstrip('\n'))
                except (ValueError,IndexError,KeyError,RecursionError):self.stats['stdout_parse_errors']+=1
        threading.Thread(target=read_stdio,daemon=True).start()
        threading.Thread(target=self.drain_errors,args=(std,'stdout'),daemon=True).start()
        if self.config.get('standalone_ecapture'):
            tls=subprocess.Popen([self.config['ecapture'],'tls','--uid',str(self.uid),'--mapsize','16',
                '--libssl',self.config['libssl'],'--listen=','--eventaddr','stdout','--logaddr','/dev/null','--hex'],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            self.children.append(tls)
            threading.Thread(target=self.read_tls,args=(tls,),daemon=True).start()
            threading.Thread(target=self.drain_errors,args=(tls,'tls'),daemon=True).start()
        discovery=threading.Thread(target=self.discover_adapters,args=(env,),daemon=True)
        discovery.start()
        try:
            while not self.stop.wait(1):
                with self.lock:
                    now=time.monotonic()
                    stale=[k for k,v in self.pending.items() if now-v['at']>5]
                    for k in stale:self.pending.pop(k,None);self.stats['unpaired_writes']+=1
                    for key,item in list(self.tls_parts.items()):
                        if now-item['at']>5:
                            self.tls_parts.pop(key,None)
                            self.invalidate(key[0],item['connection'],'tls_fragment_timeout')
                    self.opaque={key:stamp for key,stamp in self.opaque.items() if now-stamp<120}
                    for key,session in list(self.h2_sessions.items()):
                        if now-session.last>120:self.invalidate(key[0],key[2],'http2_idle_timeout')
                    expired={(key[0],key[2]) for key,value in self.http.items() if now-value.last>120}
                    for pid,connection in expired:
                        active=any((key[0],key[2])==(pid,connection) and (parser.stage!='headers' or parser.buffer) for key,parser in self.http.items())
                        if active:self.invalidate(pid,connection,'http_idle_timeout')
                        else:
                            for key in list(self.http):
                                if (key[0],key[2])==(pid,connection):self.http.pop(key,None)
                            for key in list(self.requests):
                                if (key[0],key[2])==(pid,connection):self.requests.pop(key,None)
                    report={'uid':self.uid,'updated_at':time.time(),'collector_id':self.collector_id,
                            'stats':dict(self.stats),'children_running':[std.poll() is None],
                            'adapters':dict(self.adapters),'discovery_errors':self.discovery_errors,'uncovered_targets':self.uncovered_targets,'probe_capacity':8,
                            'diagnostics':list(self.diagnostics),
                            'limits':{'stdout_bytes_per_write':CAPTURE_BYTES,'tls_bytes_per_call':CAPTURE_BYTES,'stdout_events_per_process_second':200,'stdout_events_per_second':1000,'http_body_bytes':HTTPStream.LIMIT,'export_json_bytes':3500},
                            'tls_ex_enabled':bool(self.config.get('tls_ex_enabled')),
                            'tls_protocols':['http1_content_length','http1_chunked','sse','http2_bounded','gzip','deflate'] if self.config.get('tls_enabled') or self.config.get('tls_ex_enabled') else []}
                    tmp=self.root/'status.tmp';tmp.write_text(json.dumps(report));tmp.replace(self.root/'status.json')
                if std.poll() is not None:raise RuntimeError('stdout collector exited')
        finally:
            self.stop.set();discovery.join(timeout=6)
            for p in self.children:
                if p.poll() is None:p.send_signal(signal.SIGINT)
            for p in self.children:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            self.writer.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    os.umask(0o027)
    agent=Agent(json.loads(Path(args.config).read_text()))
    signal.signal(signal.SIGTERM,lambda *_:agent.stop.set());signal.signal(signal.SIGINT,lambda *_:agent.stop.set())
    agent.start()
