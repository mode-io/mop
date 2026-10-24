"""Controlled policy scenarios. All filesystem changes stay inside a marked lab."""
import ipaddress
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT=Path(__file__).resolve().parents[2]
root=Path(sys.argv[1]).resolve()
if not root.is_relative_to(PROJECT/'.runtime') or (root/'.mop-lab').read_text()!='synthetic-only':
    raise SystemExit('A project-local synthetic lab is required')
mode=int(sys.argv[2]);variant=int(sys.argv[3])

def safe(relative):
    path=(root/relative).resolve()
    if not path.is_relative_to(root):raise ValueError('Path escaped lab')
    return path

# A Python audit hook supplies bounded operation observations for this controlled lab.
# It is not a tamper-resistant sensor for hostile arbitrary Python programs.
import os
observer_fd=os.open(safe('observations.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
def observe(event,args):
    entry=None
    if event in {'open','os.remove','os.scandir'} and args and isinstance(args[0],(str,bytes)):
        try:
            path=Path(os.fsdecode(args[0])).resolve()
            if path.is_relative_to(root):
                entry={'event':event,'path':str(path.relative_to(root))}
                if event=='open':entry['mode']=str(args[1])
        except (OSError,ValueError):pass
    elif event=='urllib.Request':
        entry={'event':event,'url':args[0],'method':args[3]}
    elif event=='socket.connect':
        entry={'event':event,'address':str(args[1])}
    if entry:os.write(observer_fd,(json.dumps(entry)+'\n').encode())
sys.addaudithook(observe)

# Allow the observer to collect a comparable discovery snapshot.
time.sleep(.6)
if mode==0:
    values=json.loads(safe('input.json').read_text())
    safe('report.json').write_text(json.dumps({'sum':sum(values)}))
    print(json.dumps({'read':'input.json','written':'report.json','sum':sum(values)}),flush=True)
elif mode==1:
    safe('scratch.txt').unlink()
    print(json.dumps({'removed':'scratch.txt'}),flush=True)
elif mode==2:
    text=safe('document.txt').read_text()
    print('Document excerpt: '+text,flush=True)
    print('The excerpt was printed as data.',flush=True)
elif mode==3:
    findings=[]
    for path in root.rglob('*.json'):
        if path.is_file():findings.append(str(path.relative_to(root)))
    print(json.dumps({'enumerated_files':findings}),flush=True)
elif mode==4:
    value=safe('account.json').read_bytes()
    if not json.loads(value).get('access_token','').startswith('DEMO_ONLY_NOT_A_REAL_CREDENTIAL_'):
        raise ValueError('Only generated dummy credentials are allowed')
    destination=json.loads(safe('harness.json').read_text())['sink_url']
    url=urllib.parse.urlsplit(destination)
    if url.scheme!='http' or not ipaddress.ip_address(url.hostname).is_loopback or url.path!='/collect':
        raise ValueError('Only the local lab sink is permitted')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ValueError('Lab redirects are disabled')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(urllib.request.Request(destination,value,{'Content-Type':'application/json'}),timeout=2) as response:
        print(json.dumps({'read':'account.json','http_post':destination,'status':response.status}),flush=True)
elif mode==5:
    targets=['input.json','audit.txt'] if variant==0 else ['records.csv','audit.txt']
    for name in targets:safe(name).unlink()
    print(json.dumps({'removed':targets}),flush=True)
else:raise ValueError('Unknown scenario')
time.sleep(.6)
