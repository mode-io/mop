#!/usr/bin/env python3
"""Run an observation-only project-local Tetragon collector in the foreground."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
VERSION='1.7.0'
DIGEST='67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-regex',required=True,help='explicit exported executable scope; e.g. /usr/bin/python3.*')
    parser.add_argument('--path-prefix',action='append',help='file permission hooks for these path prefixes; defaults to repository')
    parser.add_argument('--network',action='store_true',help='also observe TCP connection hooks; not packet contents')
    parser.add_argument('--duration',type=float,default=0,help='0 runs until Ctrl-C; positive seconds auto-stop')
    args=parser.parse_args()
    if not math.isfinite(args.duration) or args.duration<0:parser.error('duration must be finite and nonnegative')
    runtime=ROOT/'.runtime/tetragon'
    package=runtime/f'tetragon-v{VERSION}-amd64'
    archive=runtime/'verified.tar.gz'
    if not archive.exists() or not (package/'usr/local/bin/tetragon').exists():
        parser.error('Install the pinned release as described in docs/tetragon.md first')
    with archive.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest() if hasattr(hashlib,'file_digest') else hashlib.sha256(stream.read()).hexdigest()
    if digest!=DIGEST:parser.error('release checksum mismatch')
    if not Path('/sys/kernel/btf/vmlinux').is_file():parser.error('kernel BTF is unavailable')
    live=runtime/'live';live.mkdir(mode=0o700,exist_ok=True)
    policies=live/'policies';policies.mkdir(mode=0o700,exist_ok=True)
    prefixes=args.path_prefix or [str(ROOT)]
    if len(prefixes)>8 or any(not p.startswith('/') for p in prefixes):parser.error('use 1..8 absolute path prefixes')
    # JSON is valid YAML and avoids an additional YAML dependency.
    probes=[{'call':'security_file_permission','syscall':False,'return':True,
             'args':[{'index':0,'type':'file'},{'index':1,'type':'int'}],
             'returnArg':{'index':0,'type':'int'},
             'selectors':[{'matchArgs':[{'index':0,'operator':'Prefix','values':prefixes}]}]}]
    if args.network:
        probes.append({'call':'tcp_connect','syscall':False,'return':True,
                       'args':[{'index':0,'type':'sock'}],'returnArg':{'index':0,'type':'int'}})
    policy={'apiVersion':'cilium.io/v1alpha1','kind':'TracingPolicy',
            'metadata':{'name':'mop-observe'},'spec':{'kprobes':probes}}
    (policies/'observe.yaml').write_text(json.dumps(policy,indent=2)+'\n')
    export=live/'events.jsonl'
    if not export.exists():
        fd=os.open(export,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640);os.close(fd)
    if export.is_symlink():parser.error('export must not be a symlink')
    command=['sudo','-u','root','-g','#'+str(os.getgid())]
    if args.duration:command+=['timeout','--signal=TERM','--kill-after=5',str(args.duration)]
    command += [str(package/'usr/local/bin/tetragon'),
                '--bpf-lib',str(package/'usr/local/lib/tetragon/bpf'),
                '--btf','/sys/kernel/btf/vmlinux','--bpf-dir','mop-tetragon',
                '--server-address=','--health-server-address=',
                '--enable-process-cred','--enable-process-ns',
                '--tracing-policy-dir',str(policies),
                '--export-filename',str(export),'--export-file-perm','640',
                '--export-file-max-size-mb','5','--export-file-max-backups','2',
                '--export-allowlist',json.dumps({'binary_regex':[args.binary_regex]}),
                '--process-cache-size','4096']
    print('Observation only. Raw local export may include command arguments; MOP redacts before inference.',flush=True)
    print('Export: '+str(export),flush=True)
    print('Foreground collector; Ctrl-C stops it. No systemd service is installed.',flush=True)
    return subprocess.call(command)


if __name__=='__main__':
    try:raise SystemExit(main())
    except KeyboardInterrupt:raise SystemExit(130)
