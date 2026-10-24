"""Bounded passive HTTP/2 frame and HPACK decoding, without transmitting frames."""
import base64
import json
import time
import zlib
import hpack

PREFACE=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
LIMIT=262144


class Session:
    def __init__(self,agent,base,client_direction):
        self.agent=agent;self.base=base;self.client_direction=client_direction
        self.buffers={};self.decoders={};self.continuations={};self.streams={};self.preface=False;self.last=time.monotonic()

    def gap(self,reason):
        self.agent.invalidate(self.base[0],self.base[2],reason)
        raise ValueError(reason)

    def feed(self,direction,data):
        self.last=time.monotonic();buffer=self.buffers.get(direction,b'')+data
        if len(buffer)>LIMIT:self.gap('http2_buffer_limit')
        if direction==self.client_direction and not self.preface:
            if len(buffer)<len(PREFACE):self.buffers[direction]=buffer;return
            if not buffer.startswith(PREFACE):self.gap('http2_invalid_preface')
            buffer=buffer[len(PREFACE):];self.preface=True
        while len(buffer)>=9:
            length=int.from_bytes(buffer[:3],'big');kind=buffer[3];flags=buffer[4];stream=int.from_bytes(buffer[5:9],'big')&0x7fffffff
            if length>65536:self.gap('http2_frame_limit')
            if len(buffer)<9+length:break
            body=buffer[9:9+length];buffer=buffer[9+length:]
            pending=self.continuations.get(direction)
            if pending and (kind!=9 or pending['stream']!=stream):self.gap('http2_header_interleaving')
            if kind==1:
                if not stream:self.gap('http2_invalid_stream')
                if flags&8:
                    if not body or body[0]>=len(body):self.gap('http2_invalid_padding')
                    pad=body[0];body=body[1:len(body)-pad]
                if flags&32:
                    if len(body)<5:self.gap('http2_invalid_priority')
                    body=body[5:]
                pending={'stream':stream,'body':body,'end_stream':bool(flags&1)}
                self.continuations[direction]=pending
                if flags&4:self.headers(direction,pending);self.continuations.pop(direction,None)
            elif kind==9:
                if not pending:self.gap('http2_unexpected_continuation')
                pending['body']+=body
                if len(pending['body'])>16384:self.gap('http2_header_limit')
                if flags&4:self.headers(direction,pending);self.continuations.pop(direction,None)
            elif kind==0:
                item=self.streams.get((direction,stream))
                if not item:self.gap('http2_data_without_headers')
                if flags&8:
                    if not body or body[0]>=len(body):self.gap('http2_invalid_padding')
                    pad=body[0];body=body[1:len(body)-pad]
                item['body'].extend(body)
                if len(item['body'])>LIMIT:self.gap('http2_body_limit')
                if flags&1:self.finish(direction,stream)
            elif kind==3:
                for key in list(self.streams):
                    if key[1]==stream:self.streams.pop(key,None)
                self.agent.emit(self.base[0],'capture_gap',{'protocol':'http2','stream_id':stream,'reason':'stream_reset'},complete=False)
            elif kind==5:self.gap('http2_push_unsupported')
            elif kind==4:
                if stream or (flags&1 and length) or (not flags&1 and length%6):self.gap('http2_invalid_settings')
            elif kind==7:
                self.streams.clear()
                self.agent.emit(self.base[0],'capture_gap',{'protocol':'http2','reason':'goaway_observed'},complete=False)
        self.buffers[direction]=buffer

    def headers(self,direction,pending):
        decoder=self.decoders.setdefault(direction,hpack.Decoder(max_header_list_size=16384))
        try:pairs=decoder.decode(pending['body'])
        except Exception:self.gap('http2_hpack_error')
        headers={}
        for name,value in pairs:
            if (name.startswith(':') or name=='content-length') and name in headers:self.gap('http2_duplicate_pseudoheader')
            headers[name]=value
        key=(direction,pending['stream'])
        if key in self.streams:
            # Trailer fields are not mixed with the original status or authorization.
            if any(name.startswith(':') for name in headers):
                if headers.get(':status','').startswith('1'):return
                self.gap('http2_duplicate_headers')
        else:
            if len(self.streams)>=128:self.gap('http2_stream_limit')
            if ':method' in headers:
                evidence={'method':headers[':method'],'path':headers.get(':path','').split('?',1)[0],
                          'host':headers.get(':authority',''),'scheme':headers.get(':scheme','')}
                kind='http_request'
            elif ':status' in headers:
                if headers[':status'].startswith('1'):return
                evidence={'status':int(headers[':status']),'content_type':headers.get('content-type','')};kind='http_response'
            else:self.gap('http2_headers_without_identity')
            self.streams[key]={'evidence':evidence,'kind':kind,'body':bytearray(),'encoding':headers.get('content-encoding','identity'),'declared_length':headers.get('content-length')}
        if pending['end_stream']:self.finish(direction,pending['stream'])

    def finish(self,direction,stream):
        key=(direction,stream);item=self.streams[key];raw=bytes(item['body'])
        declared=item.get('declared_length')
        request=self.agent.requests.get(self.base+('h2',stream),{})
        has_body=item['evidence'].get('status') not in (204,304) and request.get('method')!='HEAD'
        if declared is not None and has_body and (not declared.isdigit() or int(declared)!=len(raw)):self.gap('http2_length_mismatch')
        encoding=item['encoding']
        if encoding in ('gzip','deflate'):
            decoder=zlib.decompressobj(31 if encoding=='gzip' else zlib.MAX_WBITS)
            try:raw=decoder.decompress(raw,LIMIT+1)
            except zlib.error:self.gap('http2_compression_error')
            if len(raw)>LIMIT or decoder.unconsumed_tail or not decoder.eof:self.gap('http2_decompression_limit')
        elif encoding not in ('identity',''):self.gap('http2_unsupported_encoding')
        try:
            text=raw.decode('utf-8')
            if '\x00' in text:raise ValueError('binary')
            try:body=json.loads(text) if text else None
            except ValueError:body=text
        except (UnicodeDecodeError,ValueError):body={'encoding':'base64','data':base64.b64encode(raw).decode(),'semantic_decoding':False}
        evidence={**item['evidence'],'http_version':'HTTP/2','stream_id':stream,'body':body}
        request_key=self.base+('h2',stream)
        if item['kind']=='http_request':
            self.agent.requests[request_key]=evidence
            if len(self.agent.requests)>256:self.gap('http2_request_limit')
        else:
            request=self.agent.requests.pop(request_key,None)
            if request:evidence['original_request']=request
            else:evidence['request_context_missing']=True
        self.agent.emit(self.base[0],item['kind'],evidence,protocol='http2',complete=True,
                        request_context_captured='original_request' in evidence if item['kind']=='http_response' else False)
        self.streams.pop(key,None)
