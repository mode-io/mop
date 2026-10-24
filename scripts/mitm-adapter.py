"""Export observed proxy traffic to MOP; never modify payloads or disable TLS validation."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import time
import zlib

ROOT=Path(os.environ.get('MOP_ROOT',str(Path(__file__).resolve().parents[1])))
spec=importlib.util.spec_from_file_location('mop_content_agent',Path(__file__).with_name('capture_export.py'))
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
LIMIT=262144


def decode(raw,encoding):
    if len(raw)>LIMIT:raise ValueError('body_limit')
    if encoding in ('gzip','deflate'):
        decoder=zlib.decompressobj(31 if encoding=='gzip' else zlib.MAX_WBITS)
        raw=decoder.decompress(raw,LIMIT+1)
        if len(raw)>LIMIT or decoder.unconsumed_tail:raise ValueError('decompression_limit')
        if not decoder.eof:raise ValueError('incomplete_compression')
    elif encoding=='br':
        import brotli
        decoder=brotli.Decompressor();result=bytearray()
        for offset in range(0,len(raw),32):
            result.extend(decoder.process(raw[offset:offset+32]))
            if len(result)>LIMIT:raise ValueError('decompression_limit')
        if not decoder.is_finished():raise ValueError('incomplete_compression')
        raw=bytes(result)
    elif encoding=='zstd':
        import zstandard
        size=zstandard.frame_content_size(raw)
        if size>LIMIT and size!=zstandard.CONTENTSIZE_UNKNOWN:raise ValueError('decompression_limit')
        raw=zstandard.ZstdDecompressor().decompress(raw,max_output_size=LIMIT)
    elif encoding not in ('','identity'):raise ValueError('unsupported_content_encoding')
    try:
        text=raw.decode('utf-8')
        if '\x00' in text:raise ValueError('binary')
    except (UnicodeDecodeError,ValueError):
        return {'encoding':'base64','data':base64.b64encode(raw).decode(),'semantic_decoding':False}
    try:return json.loads(text) if text else None
    except (ValueError,RecursionError):return text


def protobuf_fields(data):
    """Decode wire values without inventing protobuf field names or scalar types."""
    position=0;fields=[]
    def varint():
        nonlocal position
        value=0
        for shift in range(0,70,7):
            if position>=len(data):raise ValueError('truncated_varint')
            byte=data[position];position+=1;value|=(byte&127)<<shift
            if not byte&128:return value
        raise ValueError('invalid_varint')
    while position<len(data):
        if len(fields)>=256:return {'fields':fields,'remaining_bytes':len(data)-position,'schema_available':False}
        key=varint();number=key>>3;wire=key&7
        if number==0:raise ValueError('invalid_field_number')
        field={'number':number,'wire_type':wire}
        if wire==0:field['unsigned_varint']=varint()
        elif wire in (1,5):
            length=8 if wire==1 else 4
            if position+length>len(data):raise ValueError('truncated_fixed')
            field['little_endian_hex']=data[position:position+length].hex();position+=length
        elif wire==2:
            length=varint()
            if position+length>len(data):raise ValueError('truncated_bytes')
            value=data[position:position+length];position+=length
            try:
                text=value.decode('utf-8')
                if any(ord(c)<32 and c not in '\r\n\t' for c in text):raise ValueError('binary')
                field['utf8']=text
            except (UnicodeDecodeError,ValueError):field['base64']=base64.b64encode(value).decode()
        else:raise ValueError('unsupported_wire_type')
        fields.append(field)
    return {'fields':fields,'schema_available':False}


class Capture:
    def __init__(self):
        self.root=Path(os.environ.get('MOP_NETWORK_DIR',str(ROOT/'.runtime/network')))
        self.agent=core.Exporter({'uid':os.getuid(),'log_dir':str(self.root),'source':'network-proxy'})
        self.agent.excluded=lambda pid:False
        self.counts={};self.last_status=0

    def emit(self,kind,evidence,**flags):
        self.agent.emit(0,kind,evidence,adapter='mitmproxy',client_pid_inferred=False,**flags)
        self.counts[kind]=self.counts.get(kind,0)+1
        self.status()

    def status(self):
        value={'updated_at':time.time(),'children_running':[True],'stats':dict(self.agent.stats),
               'adapter':'mitmproxy','mode':os.environ.get('MOP_PROXY_MODE','web'),
               'protocols':(['tcp','tls_plaintext'] if os.environ.get('MOP_PROXY_MODE')=='tcp' else ['http1','http2','sse','websocket','grpc_frames','dns']+(['http3_reverse'] if os.environ.get('MOP_REVERSE_HTTP3')=='1' else [])),
               'scope':'connections_routed_through_proxy','pid_attribution':False}
        p=self.root/'status.tmp';p.write_text(json.dumps(value));p.replace(self.root/'status.json')

    async def running(self):
        import asyncio
        async def heartbeat():
            while True:self.status();await asyncio.sleep(2)
        self.heartbeat=asyncio.create_task(heartbeat())

    def body_result(self,message):
        raw=message.raw_content
        if raw is None:return None,{'available':False,'reason':'streamed_or_unavailable'}
        try:return decode(raw,message.headers.get('content-encoding','identity').lower()),{'available':True,'wire_bytes':len(raw)}
        except Exception as error:return None,{'available':False,'reason':str(error)[:80] if isinstance(error,ValueError) else type(error).__name__}

    @staticmethod
    def transport_data(flow):
        upstream=getattr(flow,'server_conn',None);client=getattr(flow,'client_conn',None)
        alpn=getattr(upstream,'alpn',None)
        return {'client_peer':getattr(client,'peername',None),'upstream_peer':getattr(upstream,'peername',None),
                'upstream_address':getattr(upstream,'address',None),'tls_version':getattr(upstream,'tls_version',None),
                'alpn':alpn.decode('ascii','replace') if isinstance(alpn,bytes) else alpn}

    def request_data(self,flow):
        request=flow.request
        body,body_capture=self.body_result(request)
        return {'method':request.method,'scheme':request.scheme,'host':request.host,'port':request.port,
                'path':request.path.split('?',1)[0],'http_version':request.http_version,'body':body,'body_capture':body_capture}

    def requestheaders(self,flow):
        if os.environ.get('MOP_PROXY_MODE')!='reverse':return
        import hmac
        from mitmproxy import http
        config=json.loads((ROOT/'.runtime/network/config.json').read_text())
        expected='Basic '+base64.b64encode((config['username']+':'+config['password']).encode()).decode()
        received=flow.request.headers.pop('Proxy-Authorization','')
        if not hmac.compare_digest(received,expected):
            flow.response=http.Response.make(407,b'MOP proxy authentication required',{'Proxy-Authenticate':'Basic realm="MOP"'})

    def request(self,flow):
        data=self.request_data(flow)
        self.emit('http_request',{'request_id':flow.id,**data},complete=data['body_capture']['available'])
        if flow.request.headers.get('content-type','').startswith('application/grpc'):self.grpc_frames(flow,flow.request,'client_to_server')

    def responseheaders(self,flow):
        if flow.response.headers.get('content-type','').split(';')[0].strip().lower()!='text/event-stream':return
        meta=flow.metadata.setdefault('mop_sse',{'buffer':b'','lines':[],'index':0,'bytes':0,'failed':False})
        encoding=flow.response.headers.get('content-encoding','identity').lower()
        decoder=zlib.decompressobj(31 if encoding=='gzip' else zlib.MAX_WBITS) if encoding in ('gzip','deflate') else None
        if encoding not in ('identity','','gzip','deflate'):meta['failed']=True
        request=self.request_data(flow)
        def stream(data):
            original=data
            if not data:return data
            if meta['failed']:return data
            try:
                if decoder:
                    data=decoder.decompress(data,LIMIT-meta['bytes']+1)
                    if decoder.unconsumed_tail:raise ValueError('decompression_limit')
                meta['bytes']+=len(data)
                if meta['bytes']>LIMIT:raise ValueError('stream_limit')
                meta['buffer']+=data
                import re
                while True:
                    match=re.search(b'\r\n|\r|\n',meta['buffer'])
                    if not match or (match.group()==b'\r' and match.end()==len(meta['buffer'])):break
                    line=meta['buffer'][:match.start()];meta['buffer']=meta['buffer'][match.end():]
                    if line:meta['lines'].append(line)
                    else:
                        values=[]
                        for line in meta['lines']:
                            name,sep,value=line.partition(b':')
                            if name==b'data':values.append(value[1:] if value.startswith(b' ') else value)
                        meta['lines']=[]
                        if values:
                            meta['index']+=1
                            self.emit('http_response_event',{'request_id':flow.id,'original_request':request,
                                'http_version':flow.response.http_version,'status':flow.response.status_code,
                                'event_index':meta['index'],'body':decode(b'\n'.join(values),'identity')},
                                complete=False,event_complete=True,request_context_captured=True)
            except Exception:
                meta['failed']=True
                self.emit('capture_gap',{'request_id':flow.id,'reason':'sse_capture_limit_or_decode_error'},complete=False)
            return original
        flow.response.stream=stream

    def response(self,flow):
        request=self.request_data(flow)
        common={'request_id':flow.id,'original_request':request,'status':flow.response.status_code,'transport':self.transport_data(flow),
                'http_version':flow.response.http_version,'content_type':flow.response.headers.get('content-type','')}
        if 'mop_sse' in flow.metadata:
            state=flow.metadata['mop_sse']
            self.emit('http_response_end',{**common,'events':state['index']},complete=not state['failed'],
                      trailing_event_incomplete=bool(state['buffer'] or state['lines']),request_context_captured=True)
        else:
            body,body_capture=self.body_result(flow.response)
            self.emit('http_response',{**common,'body':body},
                      complete=body_capture['available'],body_capture=body_capture,request_context_captured=True)
        if common['content_type'].startswith('application/grpc'):self.grpc_frames(flow,flow.response,'server_to_client')

    def grpc_frames(self,flow,message,direction):
        raw=message.raw_content or b'';offset=0;index=0
        while offset+5<=min(len(raw),LIMIT):
            compressed=raw[offset];length=int.from_bytes(raw[offset+1:offset+5],'big');offset+=5
            if length>LIMIT or offset+length>len(raw):break
            index+=1;data=raw[offset:offset+length];decoded=None
            try:
                if not compressed:decoded=protobuf_fields(data)
            except ValueError:pass
            self.emit('grpc_message',{'request_id':flow.id,'original_request':self.request_data(flow),
                'message_index':index,'direction':direction,'compressed':bool(compressed),'http_version':message.http_version,
                'encoding':'protobuf_base64','data':base64.b64encode(data).decode(),'wire_values':decoded},
                complete=True,protobuf_schema_available=False)
            offset+=length
        if offset!=len(raw):self.emit('capture_gap',{'request_id':flow.id,'reason':'grpc_frame_incomplete'},complete=False)

    def websocket_message(self,flow):
        message=flow.websocket.messages[-1]
        self.emit('websocket_message',{'request_id':flow.id,'original_request':self.request_data(flow),
            'direction':'client_to_server' if message.from_client else 'server_to_client',
            'body':decode(message.content,'identity') if len(message.content)<=LIMIT else {'body_omitted':True}},complete=len(message.content)<=LIMIT)

    def tcp_message(self,flow):
        self.transport(flow,'tcp_message')
    def udp_message(self,flow):
        self.transport(flow,'udp_message')
    def transport(self,flow,kind):
        message=flow.messages[-1];data=message.content
        self.emit(kind,{'connection_id':flow.id,'server_address':flow.server_conn.address,
            'direction':'client_to_server' if message.from_client else 'server_to_client',
            'body':decode(data,'identity') if len(data)<=LIMIT else {'body_omitted':True}},complete=len(data)<=LIMIT)
    def dns_request(self,flow):
        self.emit('dns_request',{'request_id':flow.id,'questions':[{'name':q.name,'type':q.type,'class':q.class_} for q in flow.request.questions]},complete=True)
    def dns_response(self,flow):
        import ipaddress
        answers=[]
        for answer in flow.response.answers:
            data=answer.data
            value=str(ipaddress.ip_address(data)) if answer.type in (1,28) and len(data) in (4,16) else base64.b64encode(data).decode()
            answers.append({'name':answer.name,'type':answer.type,'ttl':answer.ttl,'data':value})
        self.emit('dns_response',{'request_id':flow.id,'questions':[{'name':q.name,'type':q.type} for q in flow.request.questions],
                  'response_code':flow.response.response_code,'answers':answers},complete=True)

    def error(self,flow):
        self.emit('capture_gap',{'request_id':flow.id,'reason':'proxy_transport_error'},complete=False)

addons=[Capture()]
