import importlib.util
from pathlib import Path
import unittest
try:
    import hpack
except ImportError:
    hpack=None

spec=importlib.util.spec_from_file_location('capture_http2',Path(__file__).resolve().parents[1]/'scripts/capture_http2.py')
m=importlib.util.module_from_spec(spec)
if hpack is not None:spec.loader.exec_module(m)

class Agent:
    def __init__(self):self.rows=[];self.requests={};self.gaps=[]
    def emit(self,pid,kind,evidence,**flags):self.rows.append((kind,evidence,flags))
    def invalidate(self,pid,connection,reason):self.gaps.append(reason)


def frame(kind,flags,stream,data=b''):
    return len(data).to_bytes(3,'big')+bytes([kind,flags])+stream.to_bytes(4,'big')+data

@unittest.skipIf(hpack is None,'Run collector tests with system Python and python3-hpack')
class HTTP2Tests(unittest.TestCase):
    def test_interleaved_streams_keep_request_context(self):
        agent=Agent();session=m.Session(agent,(1,1,1,'ssl'),'WRITE');request=hpack.Encoder();response=hpack.Encoder()
        session.feed('WRITE',m.PREFACE+frame(4,0,0))
        for stream,path in [(1,'/one'),(3,'/two')]:
            header=request.encode([(':method','GET'),(':scheme','https'),(':authority','localhost'),(':path',path)])
            session.feed('WRITE',frame(1,5,stream,header))
        for stream,value in [(3,b'"second"'),(1,b'"first"')]:
            header=response.encode([(':status','200'),('content-type','application/json')])
            wire=frame(1,4,stream,header)+frame(0,1,stream,value)
            for i in range(0,len(wire),3):session.feed('READ',wire[i:i+3])
        rows=[r for r in agent.rows if r[0]=='http_response']
        self.assertEqual([r[1]['original_request']['path'] for r in rows],['/two','/one'])
        self.assertEqual([r[1]['body'] for r in rows],['second','first'])
        self.assertFalse(agent.requests)
    def test_continuation_and_invalid_interleaving(self):
        agent=Agent();session=m.Session(agent,(1,1,1,'ssl'),'WRITE');encoder=hpack.Encoder()
        header=encoder.encode([(':method','GET'),(':path','/'),(':scheme','https'),(':authority','localhost')])
        session.feed('WRITE',m.PREFACE+frame(1,1,1,header[:3])+frame(9,4,1,header[3:]))
        self.assertEqual(agent.rows[0][1]['path'],'/')
        session.feed('WRITE',frame(1,0,3,header[:2]))
        with self.assertRaises(ValueError):session.feed('WRITE',frame(0,1,3,b'x'))
        self.assertIn('http2_header_interleaving',agent.gaps)
    def test_missing_data_does_not_claim_complete_response(self):
        agent=Agent();session=m.Session(agent,(1,1,1,'ssl'),'WRITE');encoder=hpack.Encoder()
        session.feed('WRITE',m.PREFACE+frame(1,5,1,encoder.encode([(':method','GET'),(':path','/')])))
        server=hpack.Encoder()
        with self.assertRaises(ValueError):
            session.feed('READ',frame(1,4,1,server.encode([(':status','200'),('content-length','2')]))+frame(0,1,1,b'x'))
        self.assertIn('http2_length_mismatch',agent.gaps)
        self.assertFalse(any(r[0]=='http_response' for r in agent.rows))

    def test_compression_limit_and_binary_body(self):
        agent=Agent();session=m.Session(agent,(1,1,1,'ssl'),'WRITE');encoder=hpack.Encoder()
        session.feed('WRITE',m.PREFACE+frame(1,5,1,encoder.encode([(':method','GET'),(':path','/')])))
        server=hpack.Encoder()
        session.feed('READ',frame(1,4,1,server.encode([(':status','200')]))+frame(0,1,1,b'\0hello'))
        self.assertFalse(agent.rows[-1][1]['body']['semantic_decoding'])

if __name__=='__main__':unittest.main()
