"""Bounded loopback proxy load with observed-body and guard completion checks."""
import concurrent.futures
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]

def percentile(values, q):
    return sorted(values)[min(len(values)-1, int((len(values)-1)*q))] if values else None

def main():
    import httpx
    work = ROOT / 'artifacts' / ('network-stress-' + str(int(time.time())))
    work.mkdir(mode=0o700)
    config = json.loads((ROOT / '.runtime/network/config.json').read_text())
    proxy = 'http://' + config['username'] + ':' + config['password'] + '@127.0.0.1:18938'
    prefix = '/mop-load-' + str(time.time_ns()) + '/'
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log = (work / 'watch.log').open('w')
    watcher = subprocess.Popen([str(ROOT/'scripts/mop'), '-b', '-d', '0.5', '--duration', '150', '-p', str(os.getpid()), '--no-tetragon', '--log', str(work/'audit.jsonl')], stdout=log, stderr=subprocess.STDOUT)
    stages = []; sent = {}; peak = {}; stop = threading.Event()
    def sample():
        while not stop.wait(.5):
            for name in ('mop-tetragon', 'mop-content-1001', 'mop-network-1001'):
                try:
                    value = int(subprocess.check_output(['systemctl','show',name,'-p','MemoryCurrent','--value'], text=True, timeout=2))
                    peak[name] = max(peak.get(name,0), value)
                except (ValueError, subprocess.SubprocessError): pass
    sampler = threading.Thread(target=sample, daemon=True); sampler.start()
    def records():
        found = {}
        for path in work.glob('audit.jsonl*'):
            if path.suffix == '.lock': continue
            for line in path.read_text().splitlines():
                try: row = json.loads(line)
                except ValueError: continue
                event = row.get('event', {})
                if event.get('source') != 'network-proxy': continue
                meta = event.get('metadata', {}); evidence = meta.get('evidence', {})
                route = evidence.get('path') or evidence.get('original_request', {}).get('path','')
                if route.startswith(prefix): found[(route,meta['kind'])] = row
        return found
    try:
        time.sleep(3)
        for concurrency in (1,4,16):
            durations=[]; errors=[]
            def request(index):
                route = prefix + str(concurrency) + '/' + str(index)
                payload = {'text':'Sample document for bounded transport verification.', 'sequence':index}
                sent[route] = payload
                start = time.perf_counter()
                try:
                    with httpx.Client(proxy=proxy, trust_env=False, timeout=10) as client:
                        response = client.post('http://127.0.0.1:'+str(server.server_port)+route,json=payload)
                        response.raise_for_status()
                        assert response.json() == payload
                    durations.append((time.perf_counter()-start)*1000)
                except Exception as error: errors.append(type(error).__name__)
            begin=time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                list(pool.map(request,range(32)))
            elapsed=time.perf_counter()-begin
            stages.append({'concurrency':concurrency,'requests':32,'client_errors':errors,'wall_seconds':elapsed,'requests_per_second':32/elapsed,'request_p50_ms':percentile(durations,.5),'request_p95_ms':percentile(durations,.95)})
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            rows=records()
            if len(rows)>=2*len(sent):break
            if watcher.poll() is not None:break
            time.sleep(1)
        rows=records(); missing=[]; mismatch=[]; unknown=0; metrics={key:[] for key in ('inference_ms','queue_ms','end_to_end_ms')}
        for route,payload in sent.items():
            for kind in ('http_request','http_response'):
                row=rows.get((route,kind))
                if row is None:missing.append((route,kind));continue
                if row['event']['metadata']['evidence'].get('body')!=payload:mismatch.append((route,kind))
                unknown+=row['verdict']['category']=='unknown'
                for key in metrics: metrics[key].append(row[key])
        result={'stages':stages,'requests':len(sent),'expected_guard_records':2*len(sent),'guard_records':len(rows),'missing_records':len(missing),'body_mismatches':len(mismatch),'unknown':unknown,'guard_latency':{key:{'p50':percentile(values,.5),'p95':percentile(values,.95),'max':max(values) if values else None} for key,values in metrics.items()},'peak_service_memory_bytes':peak,'external_api_calls':0,'notes':['Loopback HTTP proxy load; TLS and other protocols are verified separately.','Client latency includes connection setup; guard inference is asynchronous.','Bounded shared-host run, not a saturation or accuracy benchmark.'],'all_verified':not missing and not mismatch and not unknown and all(not s['client_errors'] for s in stages)}
        (work/'result.json').write_text(json.dumps(result,indent=2))
        print(json.dumps({'directory':str(work),**result},indent=2))
        if not result['all_verified']:raise SystemExit(1)
    finally:
        stop.set();sampler.join(timeout=8)
        watcher.terminate()
        try:watcher.wait(timeout=15)
        except subprocess.TimeoutExpired:watcher.kill();watcher.wait()
        server.shutdown();server.server_close();log.close()

if __name__=='__main__':main()
