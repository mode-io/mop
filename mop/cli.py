from __future__ import annotations

import argparse
import asyncio
import curses
import json
import math
import os
import platform
import signal
import shutil
import sys
import time
from pathlib import Path

from .collectors import proc_watch, replay, trace_command
from .core import Engine, Event
from .audit import AuditLog
from .config import apply_config
from .ui import monitor, event_monitor


def guard_env(name, default=""):
    return os.environ.get("MOP_" + name, default)


def single_provider(args):
    from .classification import ClassificationProvider
    from .microbatch import MicroBatchProvider
    transport = ClassificationProvider(args.base_url, args.model, guard_env("API_KEY"),
        args.timeout, args.allow_remote, args.cache_policy, task=args.classification, function_task=args.function_classification, artifact_rules=args.artifact_rules, input_mode=args.input_mode)
    if args.prompt_log:
        transport.prompt_log = AuditLog(args.prompt_log, args.log_max_bytes, args.log_backups)
    return MicroBatchProvider(transport, args.batch_size, args.batch_wait_ms, args.batch_concurrency,
        pending_capacity=max(args.workers, args.batch_size * args.batch_concurrency))


def provider_from(args):
    from .model_router import ModelRouter
    import copy
    default={'models':[{'name':'openjev-core','version':'openjev-placeholder','model':args.model,
        'endpoint':args.base_url,'role':'core','state':'active','sources':[],'budget_ms':args.timeout*1000,
        'allow_remote':args.allow_remote}], 'rules':[]}
    shared_log=AuditLog(args.prompt_log,args.log_max_bytes,args.log_backups) if args.prompt_log else None
    class SharedWriter:
        def write_record(self,value):shared_log.write_record(value)
        def close(self):pass
    def factory(slot,task):
        config=copy.copy(args)
        config.base_url=slot['endpoint'];config.model=slot['model'];config.allow_remote=slot['allow_remote']
        config.classification=task
        if config.function_classification:
            config.function_classification=copy.deepcopy(config.function_classification)
            config.function_classification['prompt']+='\n'+task['prompt'][len(args.classification['prompt']):]
        # A single audit writer belongs to the core transport.
        config.prompt_log=None
        provider=single_provider(config)
        if shared_log and slot['role']=='core':provider.transport.prompt_log=SharedWriter()
        return provider
    try:
        router=ModelRouter(factory,args.classification,default)
        router.prompt_log=shared_log
        return router
    except BaseException:
        if shared_log:shared_log.close()
        raise


def options(parser, default_ui="top"):
    parser.add_argument("--input-mode", choices=["full","compact"], default="compact", help="model input view; audit events remain complete")
    parser.add_argument("--artifact-rules", action=argparse.BooleanOptionalAction, default=False, help="separate deterministic checks on generated destructive artifacts")
    parser.add_argument("--viztracer-max-functions", type=int, default=256, help="maximum function observations reviewed per capture")
    parser.add_argument("--viztracer", action=argparse.BooleanOptionalAction, default=True,
                        help="capture inputs, assignments and outputs for launched Python scripts")
    parser.add_argument("--tetragon", action=argparse.BooleanOptionalAction, default=True,
                        help="attach the shared kernel collector by default for watch")
    parser.add_argument("--tetragon-window-ms", type=float, default=250, help="kernel evidence coalescing window; 0 disables")
    parser.add_argument("--ui", choices=["top", "htop", "btop"], default=default_ui, help="presentation only; engine is shared")
    from .granularity import LEVELS
    parser.add_argument("--level", choices=LEVELS, default="event", help="inference aggregation level")
    parser.add_argument("--window-ms", type=float, default=250, help="target aggregation window (scheduler delay may add latency)")
    parser.add_argument("--max-events", type=int, default=64, help="flush a group after this many operations")
    parser.add_argument("--max-groups", type=int, default=256, help="maximum simultaneous aggregation groups")
    parser.add_argument("--batch-size", type=int, default=4, help="independent decisions per native Jev HTTP batch")
    parser.add_argument("--batch-wait-ms", type=float, default=0, help="bounded coalescing delay, distinct from semantic aggregation")
    parser.add_argument("--batch-concurrency", type=int, default=2)
    parser.add_argument("--cache-policy", choices=["native","session","isolated","off"], default="native")
    parser.add_argument("--evidence-log", help="private full bounded system evidence before model projection")
    parser.add_argument("--include-args", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--output-files", action=argparse.BooleanOptionalAction, default=True,
                        help="read bounded redacted tails of owned regular stdout/stderr files")
    parser.add_argument("--evidence", choices=["none", "runtime"], default="runtime")
    parser.add_argument("--review-interval", type=float, default=30, help="periodic process review seconds; 0 means discovery only")
    parser.add_argument("--history-limit", type=int, default=512)
    parser.set_defaults(classification=None, function_classification=None)
    from .config import DEFAULT_CONFIG
    parser.add_argument("--config", default=guard_env("CONFIG", str(DEFAULT_CONFIG)),
                        help="classification configuration; default is independent of working directory")
    parser.add_argument("--context", help="JSON task_id, window_id, user_intent, authorization")
    parser.add_argument("--log-max-bytes", type=int, default=10485760)
    parser.add_argument("--log-backups", type=int, default=3)
    parser.add_argument("--drain-timeout", type=float, default=10)
    parser.add_argument("--prompt-log", help="private log of exact model request payloads; excludes HTTP credentials")
    parser.add_argument("--summary", help="append final machine-readable summary to private JSONL")
    parser.add_argument("--base-url", default=guard_env("BASE_URL", "http://127.0.0.1:18936"))
    parser.add_argument("--model", default=guard_env("MODEL", "mop-open-jev-2b"))
    parser.add_argument("--allow-remote", action="store_true",
                        default=guard_env("ALLOW_REMOTE") == "1")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--capacity", type=int, default=256)
    parser.add_argument("--log", help="private JSONL audit path; may contain caller-supplied metadata")


def pid_list(value):
    try: result = [int(item) for item in value.split(',')]
    except ValueError: raise argparse.ArgumentTypeError('Use comma-separated positive PIDs') from None
    if not result or len(result)>4096 or any(pid<1 for pid in result):
        raise argparse.ArgumentTypeError('Use 1..4096 positive PIDs')
    return result


def parser(default_ui="top", advanced=False):
    brand = {"top": "MOP", "htop": "H-MOP", "btop": "B-MOP"}[default_ui]
    p = argparse.ArgumentParser(description=brand + ": process monitor with local AI security review")
    from . import __version__
    p.add_argument("--version", action="version", version=brand + " " + __version__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("doctor")
    from .variables import configure_parser
    configure_parser(sub.add_parser("variables", help="trace selected Python variable uses"))
    report = sub.add_parser("inspect", help="browse a saved variable report; no inference")
    report.add_argument("path")
    report.add_argument("--plain", action="store_true", help="print a readable report without curses")
    watch = sub.add_parser("watch")
    options(watch, default_ui)
    watch.add_argument("--daemon-owner", action="store_true", help=argparse.SUPPRESS)
    watch.add_argument("--standalone", action="store_true", help="run a separate observer")
    watch.add_argument("--duration", type=float, default=None, help="seconds; default runs until quit")
    watch.add_argument("-d", "--interval", type=float, default=1, help="refresh interval in seconds")
    watch.add_argument("--all-users", action="store_true")
    watch.add_argument("-H", "--threads", action="store_true", help="show threads")
    watch.add_argument("-b", "--plain", action="store_true", help="batch JSON output without a terminal")
    watch.add_argument("-u", "--user", help="display only this user name or UID")
    watch.add_argument("-p", "--pids", type=pid_list, default=[], help="display comma-separated PIDs")
    watch.add_argument("-n", "--iterations", type=int, help="exit after this many display updates")
    watch.add_argument("--tetragon-log", help="follow a local Tetragon JSONL export alongside process snapshots")
    trace = sub.add_parser("trace")
    options(trace, default_ui)
    trace.add_argument("--pid", type=int, help="explicitly attach to an existing process; detach at timeout")
    trace.add_argument("--scope", choices=["all", "security"], default="security")
    trace.add_argument("--duration", type=float, default=10)
    trace.add_argument("--tui", action="store_true", help="live syscall verdict terminal")
    trace.add_argument("--sudo", action="store_true", help="explicit privileged tracer; command retains current user")
    trace.add_argument("command", nargs=argparse.REMAINDER)
    tetra = sub.add_parser("tetragon", help="classify Tetragon JSONL events with the existing engine")
    options(tetra, default_ui)
    tetra.add_argument("path")
    tetra.add_argument("--follow", action="store_true")
    tetra.add_argument("--from-end", action="store_true")
    tetra.add_argument("--duration", type=float)
    tetra.add_argument("--all-users", action="store_true", help="default accepts current UID only")
    rep = sub.add_parser("replay")
    options(rep, default_ui)
    rep.add_argument("path")
    gate = sub.add_parser("gate", help="review a command before starting it")
    options(gate, default_ui)
    gate.add_argument('--mode', choices=['observe','approve','enforce'], default='approve')
    gate.add_argument('command', nargs=argparse.REMAINDER)
    check = sub.add_parser("check")
    options(check, default_ui)
    assess = sub.add_parser("assess", help="classify a supplied operation and print its category")
    options(assess, default_ui)
    assess.add_argument("path", help="JSON object with context and operation fields")
    review = sub.add_parser("review", help="review a running process with bounded runtime evidence")
    options(review, default_ui)
    review.add_argument("--pid", type=int, required=True)
    review.add_argument("--task-log", action="append", default=[], help="explicit regular task log; at most four")
    review.add_argument("--output-root", action="append", default=[], help="allowed directory for regular stdout/stderr files")
    review.add_argument("--duration", type=float, default=None, help="repeat review for this many seconds; otherwise review once")
    capture = sub.add_parser("capture", help="launch a task and classify windows of its stdout/stderr")
    options(capture, default_ui)
    capture.add_argument("--duration", type=float, default=None)
    capture.add_argument("--decision-tokens", type=int, default=2048)
    capture.add_argument("--capture-window", type=float, default=1, help="output window seconds")
    capture.add_argument("command", nargs=argparse.REMAINDER)
    run = sub.add_parser("run", help="execute any command and review observed facts with the shared safety policy")
    options(run, default_ui)
    run.add_argument("--duration", type=float, default=None)
    run.add_argument("--capture-window", type=float, default=1)
    run.add_argument("--decision-tokens", type=int, default=2048)
    run.add_argument("command", nargs=argparse.REMAINDER)
    proxy = sub.add_parser("proxy", help="review loopback JSON/SSE API calls with original request context")
    options(proxy, default_ui)
    proxy.add_argument("--listen-port", type=int, default=18937)
    proxy.add_argument("--decision-tokens", type=int, default=2048, help="per-decision input budget including original request; 512..4096")
    proxy.add_argument("--upstream", default="http://127.0.0.1:18936")
    proxy.add_argument("--duration", type=float, default=None)
    if not advanced:
        common = {'-h','--help','--config','--log','--prompt-log','--duration'}
        specific = {'watch':{'-d','-H','-b','-u','-p','-n'},
                    'proxy':{'--listen-port','--upstream'}, 'review':{'--pid'},
                    'trace':{'--pid','--sudo','--tui'}, 'inspect':{'--plain'}}
        for name, command_parser in sub.choices.items():
            for action in command_parser._actions:
                if action.option_strings and not set(action.option_strings) & (common | specific.get(name,set())):
                    action.help = argparse.SUPPRESS
            command_parser.epilog = 'Advanced options: add --help-all. Defaults are shared through the config file.'
        watch.epilog = 'Keys: P/M/T sort, c command, u user, k signal, r nice, H threads, Enter details. Other commands: mop run -- COMMAND; mop proxy; mop doctor. Advanced options: mop --help-all.'
    return p


def doctor():
    report = {
        "kernel": platform.release(), "architecture": platform.machine(),
        "uid": os.getuid(), "proc": Path("/proc/self/stat").exists(),
        "strace": shutil.which("strace"),
        "ptrace_scope": Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() if Path("/proc/sys/kernel/yama/ptrace_scope").exists() else "unknown",
                "btf": Path("/sys/kernel/btf/vmlinux").exists(),
        "lsm": "unreadable",
        "coverage": "proc snapshots and command-scoped tracing; classification only",
        "external_model_calls": 0,
    }
    try:
        report["lsm"] = Path("/sys/kernel/security/lsm").read_text().strip()
    except OSError:
        pass
    content_status = Path('/var/log/mop-content') / str(os.getuid()) / 'status.json'
    try:
        with content_status.open('rb') as stream:
            raw_status = stream.read(16385)
        if len(raw_status) > 16384:
            raise ValueError('Oversized collector status')
        report['system_content'] = json.loads(raw_status)
    except (OSError, ValueError):
        report['system_content'] = {'status': 'unavailable', 'setup': 'bash scripts/setup.sh'}
    print(json.dumps(report, indent=2))


async def execute(args, screen=None):
    if args.action=='watch' and not args.daemon_owner and not args.standalone:
        from .daemon import socket_path, watch as remote_watch
        if socket_path().exists():return await remote_watch(args,screen)
    provider = provider_from(args)
    if args.action == 'gate':
        from .gate import execute as gate_execute
        try:return await gate_execute(args,provider)
        finally:await provider.aclose()
    if args.action == "assess":
        from .assessment import assess
        try:
            return await assess(args, provider)
        finally:
            if hasattr(provider,"aclose"):await provider.aclose()
    engine = await Engine(provider, args.workers, args.capacity, args.log,
                          args.task_context, args.log_max_bytes, args.log_backups,
                          args.level, args.window_ms, args.max_events, args.max_groups, args.history_limit).start()
    if args.evidence == "runtime" or args.action == "review":
        from .evidence import EvidenceCollector
        engine.evidence_collector = EvidenceCollector(logs=getattr(args, "task_log", ()),
            output_roots=getattr(args, "output_root", ()), include_args=args.include_args, auto_output=args.output_files,
            evidence_log=AuditLog(args.evidence_log,args.log_max_bytes,args.log_backups) if args.evidence_log else None)
    engine.review_interval = args.review_interval
    if args.action == 'watch' and args.iterations is not None and args.iterations < 1:
        await engine.close(args.drain_timeout)
        raise ValueError('iterations must be positive')
    if args.action == "watch" and args.tetragon and not args.tetragon_log:
        args.tetragon_log = "/var/log/mop-tetragon/events.jsonl"
        try:
            check = await asyncio.create_subprocess_exec('systemctl', 'is-active', '--quiet', 'mop-tetragon.service', stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            kernel_active = await check.wait() == 0
        except OSError:
            kernel_active = False
        if not kernel_active:
            args.tetragon_log = None
            args.tetragon = False
            engine.stats['kernel_source_unavailable'] += 1
            print('MOP: kernel collector unavailable; process monitoring remains active.',file=sys.stderr)
    result = 0
    source_task = None
    ambient_task = None
    network_tasks = []
    command_review = None
    daemon_server = None
    if args.action=='watch' and args.daemon_owner:
        from .daemon import Server
        daemon_server=Server(engine)
        try:await daemon_server.start()
        except BaseException:await engine.close();raise
    try:
        if args.action == 'watch' and Path('/var/log/mop-content/%d/events.jsonl' % os.getuid()).exists():
            from .ambient import follow
            ambient_task = asyncio.create_task(follow(engine))
            engine.stats['ambient_enabled'] = 1
        from .paths import runtime_root
        network_root=runtime_root()/'network'
        network_sources=[(network_root/'events.jsonl','network'),(network_root/'tcp/events.jsonl','network_tcp')]
        network_sources.extend((folder/'events.jsonl','network_'+folder.name.replace('-','_')) for folder in sorted(network_root.glob('reverse-*'))[:16] if folder.is_dir())
        for network_log,prefix in network_sources:
            if args.action=='watch' and (network_log.exists() or (network_log.parent/'status.json').exists()):
                from .ambient import follow
                network_tasks.append(asyncio.create_task(follow(engine,network_log,source='network-proxy',owner=os.getuid(),prefix=prefix)))
                engine.stats[prefix+'_enabled']=1
        if args.action == "watch" and getattr(args, "tetragon_log", None):
            from .tetragon import consume, open_regular
            try:
                with open_regular(args.tetragon_log): pass
            except (OSError,ValueError):
                if args.tetragon_log != '/var/log/mop-tetragon/events.jsonl': raise
                engine.stats['kernel_source_unavailable'] += 1
                print('MOP: kernel event log unavailable; process monitoring remains active.',file=sys.stderr)
            else:
                source_task = asyncio.create_task(consume(engine, args.tetragon_log, follow=True, from_end=True,
                    uid=None if args.all_users else os.getuid(), include_args=args.include_args, window_ms=args.tetragon_window_ms,
                    service_name="mop-tetragon.service" if args.tetragon_log == "/var/log/mop-tetragon/events.jsonl" else None))
        if args.action == "run":
            from .command_review import CommandReview
            from .content import capture_command
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            command_review = CommandReview(engine, command, args.decision_tokens)
            result = await capture_command(command_review, command, args.duration, args.capture_window)
        elif args.action == "capture":
            from .viztracer_capture import capture_python
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            from .command_review import CommandReview
            command_review = CommandReview(engine, command, args.decision_tokens)
            result = await capture_python(command_review, command, args.duration, args.capture_window, enabled=args.viztracer, max_functions=args.viztracer_max_functions)
        elif args.action == "proxy":
            from .proxy import run_proxy
            await run_proxy(engine, args.upstream, args.listen_port, args.duration, args.decision_tokens)
        elif args.action == "review":
            from .evidence import process_identity
            start_ticks, name, _ = process_identity(args.pid)
            deadline = time.monotonic() + args.duration if args.duration is not None else None
            while True:
                engine.submit(Event("process_review", "proc-review", args.pid, args.pid, name,
                    metadata={"start_ticks": start_ticks, "not_a_syscall": True}))
                await engine.queue.join()
                if engine.recent:
                    rec = engine.recent[-1]
                    print(json.dumps({"pid": args.pid, "verdict": rec["verdict"],
                        "inference_ms": rec["inference_ms"], "evidence_available": "runtime_evidence" in rec["event"]["metadata"]}), flush=True)
                if deadline is None or time.monotonic() >= deadline: break
                await asyncio.sleep(min(args.review_interval or 30, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline: break
        elif args.action == "check":
            engine.submit(Event("adapter_probe", "synthetic-check", metadata={"synthetic": True}))
        elif args.action == "watch":
            if screen is not None:
                await monitor(screen, engine, args.duration, args.interval, args.all_users, args.threads, ui=args.ui,
                              user_filter=args.user, pid_filter=args.pids, iterations=args.iterations)
            else:
                def display(rows, eng):
                    if args.daemon_owner:return
                    from .security_view import advice_index, indexed_advice
                    indexed = advice_index(eng.latest_advice.values())
                    print(json.dumps({"tasks": len(rows), "processes": [dict(row, advice=indexed_advice(row,indexed)) for row in rows],
                        "system": getattr(eng,'process_metrics',{}), "review_scope": 'all_users' if args.all_users else 'current_user', **eng.summary()}, indent=2), flush=True)
                await proc_watch(engine, args.duration, args.interval,
                    args.all_users, args.threads, display, iterations=args.iterations,
                    user_filter=args.user, pid_filter=args.pids, view_all_users=True)
        elif args.action == "trace":
            cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
            if screen is not None:
                task = asyncio.create_task(trace_command(engine, cmd, args.scope, args.duration, args.sudo, args.include_args, args.pid))
                result = await event_monitor(screen, engine, task, ui=args.ui)
            else:
                result = await trace_command(engine, cmd, args.scope, args.duration, args.sudo, args.include_args, args.pid)
        elif args.action == "tetragon":
            from .tetragon import consume
            result = await consume(engine, args.path, args.follow, args.from_end, args.duration,
                uid=None if args.all_users else os.getuid(), include_args=args.include_args, window_ms=args.tetragon_window_ms)
        elif args.action == "replay":
            await replay(engine, args.path)
    finally:
        if daemon_server:await daemon_server.close()
        for network_task in network_tasks:network_task.cancel()
        if network_tasks:await asyncio.gather(*network_tasks,return_exceptions=True)
        if ambient_task:
            ambient_task.cancel()
            ambient_result = await asyncio.gather(ambient_task, return_exceptions=True)
            if any(isinstance(value, Exception) for value in ambient_result):
                engine.stats['ambient_errors'] += 1
        if source_task:
            if not source_task.done(): source_task.cancel()
            source_results = await asyncio.gather(source_task, return_exceptions=True)
            if any(isinstance(value, Exception) for value in source_results):
                result = 2
        await engine.close(args.drain_timeout)
        if command_review is not None:
            command_review.print_results()
        summary = engine.summary()
        summary["ui"] = args.ui
        if args.summary:
            output = AuditLog(args.summary, args.log_max_bytes, args.log_backups)
            try:
                output.write_record(summary)
            finally:
                output.close()
        if screen is None and args.action not in {"capture", "run"}:
            print(json.dumps({"summary": summary}, indent=2))
    if args.action in {"check", "review", "capture", "run"} and (engine.stats["errors"] or engine.stats["unknown"] or (command_review is not None and command_review.failed)) and result == 0:
        return 2
    if args.action == "tetragon" and (engine.stats['errors'] or engine.stats['tetragon_invalid'] or engine.stats['tetragon_oversized']):
        return 2
    return result


async def run_with_signals(args, screen=None):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        return await execute(args, screen)
    except asyncio.CancelledError:
        return 143
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


def main(default_ui="top", argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    boundary = argv.index('--') if '--' in argv else len(argv)
    advanced = '--help-all' in argv[:boundary]
    argv = [('--help' if i<boundary and value=='--help-all' else value) for i,value in enumerate(argv)]
    if argv and argv[0]=="daemon":
        from .daemon import main as daemon_main
        return daemon_main(argv[1:])
    if argv and argv[0] in {"models", "rules"}:
        from .model_commands import main as model_main
        return model_main(argv)
    commands = {"gate", "doctor", "watch", "trace", "replay", "check", "assess", "review", "capture", "run", "proxy", "variables", "inspect", "tetragon"}
    if not argv or (argv[0] not in commands and argv[0] not in {"-h", "--help", "--version"}):
        argv.insert(0, "watch")
    if argv and argv[0] in {'--help','-h'}: argv.insert(0,'watch')
    args = parser(default_ui,advanced=advanced).parse_args(argv)
    if args.action == "doctor":
        doctor()
        return 0
    try:
        if args.action == "variables":
            from .variables import execute as trace_variables
            return trace_variables(args)
        if args.action == "inspect":
            from .report_ui import inspect_report
            return inspect_report(args.path, args.plain)
        args = apply_config(args, argv)
        if (getattr(args, "duration", None) is not None and (not math.isfinite(args.duration) or args.duration <= 0)) or not math.isfinite(getattr(args,"interval",1)) or getattr(args, "interval", 1) <= 0:
            raise ValueError("duration and interval must be finite and positive")
        if (args.action == "watch" and not args.plain) or (args.action == "trace" and args.tui):
            if not sys.stdout.isatty():
                raise ValueError("use --plain when stdout is not a terminal")
            return curses.wrapper(lambda screen: asyncio.run(run_with_signals(args, screen)))
        return asyncio.run(run_with_signals(args))
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Do not accidentally print endpoint credentials or response bodies.
        print("MOP error: " + type(error).__name__ +
              (": " + str(error) if isinstance(error, ValueError) else ""), file=sys.stderr)
        return 2


def hmain():
    return main("htop")


def bmain():
    return main("btop")


if __name__ == "__main__":
    sys.exit(main())
