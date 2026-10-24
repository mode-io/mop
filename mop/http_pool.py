"""Small thread-safe HTTP keep-alive cache; no redirects, proxies or error-body logging."""
import http.client
import threading
import time
from collections import Counter
from urllib.parse import urlsplit


class HTTPPool:
    def __init__(self, base_url, timeout, max_idle=8, idle_seconds=4):
        self.url=urlsplit(base_url)
        self.timeout,self.max_idle,self.idle_seconds=timeout,max_idle,idle_seconds
        self.idle=[];self.lock=threading.Lock();self.closed=False;self.stats=Counter()

    def take(self):
        with self.lock:
            if self.closed:raise RuntimeError('HTTP transport closed')
            while self.idle:
                connection,returned=self.idle.pop()
                if time.monotonic()-returned<=self.idle_seconds and connection.sock is not None:
                    self.stats['connections_reused']+=1
                    return connection,True
                connection.close()
            self.stats['connections_created']+=1
        cls=http.client.HTTPSConnection if self.url.scheme=='https' else http.client.HTTPConnection
        return cls(self.url.hostname,self.url.port,timeout=self.timeout),False

    def post(self, suffix, body, headers):
        for attempt in range(2):
            connection,reused=self.take();keep=False
            try:
                connection.request('POST',self.url.path.rstrip('/')+suffix,body=body,headers=headers)
                response=connection.getresponse()
                raw=response.read(1024*1024+1)
                if len(raw)>1024*1024:raise ValueError('oversized model response')
                if not 200<=response.status<300:raise ValueError('model HTTP status '+str(response.status))
                keep=not response.will_close
                return raw
            except (http.client.RemoteDisconnected,BrokenPipeError,ConnectionResetError):
                if not reused or attempt:raise
                with self.lock:self.stats['stale_connection_retries']+=1
            finally:
                with self.lock:
                    if keep and not self.closed and len(self.idle)<self.max_idle:
                        self.idle.append((connection,time.monotonic()))
                    else:connection.close()
        raise RuntimeError('HTTP request failed')

    def close(self):
        with self.lock:
            self.closed=True
            for connection,_ in self.idle:connection.close()
            self.idle.clear()

    def summary(self):
        with self.lock:return {**dict(self.stats),'idle_connections':len(self.idle)}
