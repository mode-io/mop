#!/usr/bin/env python3
"""Enable bounded ancestor/stack evidence with rollback on startup failure."""
import argparse,json,os,subprocess,time
from pathlib import Path
if os.geteuid()!=0:raise SystemExit('Run with sudo')
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--stacks',action='store_true',help='Experimental on this kernel; requires event-level verification')
options=parser.parse_args()
root=Path('/opt/mop-tetragon')
policy=root/'policies/observe.yaml';config=root/'conf/enable-ancestors'
old_policy=policy.read_text();old_config=config.read_text() if config.exists() else None
backup=root/'advanced-backup';backup.mkdir(exist_ok=True)
(backup/'observe.yaml').write_text(old_policy)
if old_config is not None:(backup/'enable-ancestors').write_text(old_config)
value=json.loads(old_policy);probes=value['spec']['kprobes']
for probe in probes:
 if probe['call']=='sys_openat':
  for selector in probe.get('selectors',[]):selector['matchActions']=[{'action':'Post',**({'kernelStackTrace':True} if options.stacks else {})}]
for call,args in [('sys_ptrace',[{'index':0,'type':'long'},{'index':1,'type':'int'}]),('sys_setns',[{'index':0,'type':'int'},{'index':1,'type':'int'}])]:
 if not any(p['call']==call for p in probes):
  probes.append({'call':call,'syscall':True,'return':True,'args':args,'returnArg':{'index':0,'type':'int'},
                 'selectors':[{'matchActions':[{'action':'Post',**({'kernelStackTrace':True} if options.stacks else {})}]}]})
if not options.stacks:
 for probe in probes:
  for selector in probe.get('selectors',[]):
   for action in selector.get('matchActions',[]):action.pop('kernelStackTrace',None)
policy.write_text(json.dumps(value,indent=2))
config.write_text('base,kprobe\n')
started=time.time()
try:
 subprocess.run(['systemctl','restart','mop-tetragon.service'],check=True)
 for _ in range(60):
  log=subprocess.check_output(['journalctl','-u','mop-tetragon.service','--since','@'+str(int(started)),'--no-pager'],text=True)
  if 'Listening for events...' in log:
   print('Advanced policies loaded: ancestors, ptrace and setns. Stack option: '+str(options.stacks)+'. Verify actual events separately.');break
  time.sleep(.5)
 else:raise RuntimeError('collector readiness timeout')
except BaseException:
 policy.write_text(old_policy)
 if old_config is None:config.unlink(missing_ok=True)
 else:config.write_text(old_config)
 subprocess.run(['systemctl','restart','mop-tetragon.service'],check=True)
 raise
