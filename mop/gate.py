"""Explicit pre-execution guard for commands launched through MOP."""
import asyncio
from dataclasses import asdict
import fcntl
import json
import os
import sys
import time
import uuid
from .core import Event
from .audit import AuditLog
from .model_slots import state_root


def action(category,mode,approved=False):
    if mode=='observe':return 'allow'
    if category=='normal':return 'allow'
    if category=='high_risk':return 'deny'
    if mode=='approve':return 'allow' if approved else 'approval_required'
    return 'deny'


def audit(record):
    root=state_root();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(root/'gate.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        log=AuditLog(root/'gate.jsonl')
        try:log.write_record(record)
        finally:log.close()
    finally:os.close(fd)


async def execute(args,provider):
    command=args.command[1:] if args.command[:1]==['--'] else args.command
    if not command:raise ValueError('Use mop gate -- COMMAND')
    if tuple(provider.labels)!=('normal','suspicious','high_risk'):raise ValueError('Command gating requires normal/suspicious/high_risk categories')
    from .content import command_arguments
    observed_command=command_arguments(command)
    event=Event('command_proposal','command-input',os.getpid(),os.getpid(),'mop',phase='proposed',
                metadata={'command':observed_command,'cwd':os.getcwd(),'uid':os.getuid(),'parent_pid':os.getppid()})
    # Input describes a proposed command; it is never presented as an observed execution.
    start=time.monotonic();verdict=await provider.infer(event);approved=False
    if observed_command.get('truncated') or '[REDACTED' in observed_command['text']:
        verdict.model_assessment={'category':verdict.category,'reason':'Command evidence was truncated or redacted'}
        verdict.category='unknown';verdict.confidence=None;verdict.probabilities={}
        verdict.reason='Command evidence was truncated or redacted; review is incomplete'
    result=action(verdict.category,args.mode)
    gate_id=uuid.uuid4().hex
    record={'id':gate_id,'timestamp':time.time(),'mode':args.mode,'category':verdict.category,
            'verdict':asdict(verdict),'review_ms':(time.monotonic()-start)*1000,'command':observed_command,'executed':False}
    print('MOP gate: '+verdict.category+' | '+result,flush=True)
    audit({**record,'stage':'review','action':result})
    if result=='approval_required' and sys.stdin.isatty():
        print('Command: '+observed_command['text'],flush=True)
        approved=(await asyncio.to_thread(input,'Approve this command? Type yes: ')).strip()=='yes'
        result=action(verdict.category,args.mode,approved)
    if result!='allow':
        audit({**record,'stage':'decision','action':'deny','approved':False})
        print('Command was not started.',flush=True);return 3
    audit({**record,'stage':'decision','action':'allow','approved':approved})
    try:process=await asyncio.create_subprocess_exec(*command)
    except OSError as error:
        audit({**record,'stage':'launch_error','action':'not_started','error':type(error).__name__})
        raise
    try:code=await process.wait()
    except asyncio.CancelledError:
        if process.returncode is None:process.terminate()
        try:await asyncio.wait_for(process.wait(),5)
        except asyncio.TimeoutError:process.kill();await process.wait()
        raise
    audit({**record,'stage':'exit','action':'executed','executed':True,'pid':process.pid,'exit_code':code,'approved':approved})
    return code if code>=0 else 128-code
