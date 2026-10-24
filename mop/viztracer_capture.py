"""Opt-in launch boundary with default Python function capture; no process attachment."""
import ast
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from .content import capture_command
from .core import Event
from .processes import terminate_group
from .viztracer_import import convert, load


def script_command(command):
    if not command or not re.fullmatch(r'python(?:\d+(?:\.\d+)*)?(?:\.exe)?', Path(command[0]).name): return None
    index=1
    while index<len(command) and command[index] in ('-u','-B','-O','-OO'):index+=1
    if index>=len(command) or command[index].startswith('-') or not command[index].endswith('.py'):return None
    executable=shutil.which(command[0])
    if not executable:raise ValueError('Python interpreter not found')
    script=Path(command[index]).resolve()
    if not script.is_file():raise ValueError('Python script not found')
    return executable,command[1:index],script,command[index+1:]


async def runtime_info(executable, flags):
    code=('import json,threading,concurrent.futures,importlib.metadata; '
          'print(json.dumps({"version":importlib.metadata.version("viztracer"),'
          '"threading":threading.__file__,"futures":concurrent.futures.__file__}))')
    proc=await asyncio.create_subprocess_exec(executable,*flags,'-c',code,
        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,start_new_session=True)
    try:
        output,_=await asyncio.wait_for(proc.communicate(),10)
        if proc.returncode or len(output)>8192:raise ValueError('VizTracer is unavailable in the selected interpreter; install viztracer==1.1.1 there or use --no-viztracer')
        result=json.loads(output)
        if result.get('version')!='1.1.1':raise ValueError('Function capture requires viztracer==1.1.1 in the selected interpreter')
        return result
    finally:await terminate_group(proc)


async def capture_python(engine, command, duration=None, window_seconds=1, enabled=True, passthrough=True, max_functions=256):
    selected=script_command(command) if enabled else None
    if selected is None:
        engine.stats['viztracer_skipped_commands']+=1
        return await capture_command(engine,command,duration,window_seconds,passthrough)
    executable,flags,script,arguments=selected
    info=await runtime_info(executable,flags)
    with script.open("rb") as source_file: source=source_file.read(1024*1024+1)
    if len(source)>1024*1024:raise ValueError('Function capture source exceeds 1 MiB')
    tree=ast.parse(source,filename=str(script))
    functions=sorted({node.name for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))})
    if len(functions)>256:raise ValueError('Function capture supports at most 256 declared function names')
    pattern='^(?:'+'|'.join(re.escape(name) for name in functions)+')$' if functions else '(?!)'
    from .paths import runtime_root
    root=runtime_root()/'function-captures';root.mkdir(parents=True,exist_ok=True,mode=0o700)
    directory=Path(tempfile.mkdtemp(prefix='capture-',dir=root))
    trace=directory/'trace.json'
    wrapped=[executable,*flags,'-m','viztracer','--quiet','--tracer_entries','20000',
             '--ignore_c_function','--ignore_multiprocess','--log_func_args','--log_func_retval',
             '--log_func_exec',pattern,'--include_files',str(script),info['threading'],str(Path(info['futures']).parent),
             '--output_file',str(trace),'--',str(script),*arguments]
    engine.stats['viztracer_started']+=1
    result=await capture_command(engine,wrapped,duration,window_seconds,passthrough)
    if not trace.exists():
        engine.stats['viztracer_capture_errors']+=1
        if result:return result
        raise ValueError('Function trace was not saved; internal coverage unavailable')
    try:events=await asyncio.to_thread(lambda: convert(load(trace),script.parent))
    except (ValueError,OSError,TypeError):
        engine.stats['viztracer_capture_errors']+=1
        raise ValueError('Function trace is incomplete or invalid; internal coverage unavailable') from None
    if not events:
        engine.stats['viztracer_no_function_calls']+=1
        print('MOP: no Python function calls captured; internal coverage unavailable.',file=sys.stderr)
    omitted=max(0,len(events)-max_functions)
    if omitted:
        engine.stats['viztracer_unreviewed_functions']+=omitted
        engine.stats['log_errors']+=1
        print(f'MOP: function review budget reached; {omitted} calls remain in the private trace but are not reviewed.',file=sys.stderr)
    with (directory/'mop-events.jsonl').open('x',encoding='utf-8') as output:
        for index,raw in enumerate(events):
            raw['metadata']['workload_exit_code']=result
            output.write(json.dumps(raw,ensure_ascii=False)+'\n')
            if index >= max_functions: continue
            while engine.queue.full():await asyncio.sleep(.01)
            engine.submit(Event(**raw))
            engine.stats['viztracer_function_events']+=1
    print('MOP function evidence: '+str(directory/'mop-events.jsonl'),file=sys.stderr)
    return result
