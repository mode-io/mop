"""JSON config with CLI > dedicated environment > file > built-in precedence."""
import json
import math
import os
from pathlib import Path

PROJECT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "mop.json"
DEFAULT_CONFIG = PROJECT_CONFIG if PROJECT_CONFIG.exists() else Path(__file__).with_name("default.json")

FIELDS = {
    "input_mode": str,
    "artifact_rules": bool,
    "viztracer": bool, "viztracer_max_functions": int,
    "tetragon": bool, "tetragon_window_ms": (int,float), "tetragon_log": str, "evidence_log": str, "include_args": bool, "output_files": bool,
    "evidence": str, "review_interval": (int, float),
    "history_limit": int, "classification": dict, "function_classification": dict,
    "ui": str, "base_url": str, "model": str, "allow_remote": bool,
    "timeout": (int, float), "workers": int,
    "capacity": int, "log": str, "log_max_bytes": int, "log_backups": int,
    "drain_timeout": (int, float), "context": str, "prompt_log": str,
    "batch_size": int, "batch_wait_ms": (int,float), "batch_concurrency": int, "cache_policy": str,
    "level": str, "window_ms": (int, float), "max_events": int, "max_groups": int,
}
ENV = {"base_url": "MOP_BASE_URL", "model": "MOP_MODEL", "allow_remote": "MOP_ALLOW_REMOTE"}


def read_json(path, limit=16384):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("configuration exceeds size limit")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError("invalid JSON configuration") from None
    if not isinstance(result, dict):
        raise ValueError("configuration must be a JSON object")
    return result


def apply_config(args, argv):
    if getattr(args, "config", None):
        values = read_json(args.config)
        for key, value in values.items():
            if key not in FIELDS or type(value) not in (
                    FIELDS[key] if isinstance(FIELDS[key], tuple) else (FIELDS[key],)):
                raise ValueError("unknown config field or invalid type: " + key)
            flags = argv[:argv.index("--")] if "--" in argv else argv
            cli_present = any(x == "--" + key.replace("_", "-") or
                              x.startswith("--" + key.replace("_", "-") + "=") or
                              x == "--no-" + key.replace("_", "-") for x in flags)
            if not cli_present and (key not in ENV or ENV[key] not in os.environ):
                if key in {"log", "context", "prompt_log", "evidence_log", "tetragon_log"} and value and not Path(value).is_absolute():
                    value = str(Path(args.config).resolve().parent / value)
                setattr(args, key, value)
    source = getattr(args, 'tetragon_log', None) if args.action == 'watch' else getattr(args, 'path', None) if args.action == 'tetragon' else None
    if source and any(Path(source).resolve() == Path(value).resolve() for value in
                      (getattr(args, key, None) for key in ('log', 'summary', 'prompt_log', 'evidence_log')) if value):
        raise ValueError('Tetragon source must be separate from output logs')
    if not math.isfinite(args.tetragon_window_ms) or not 0 <= args.tetragon_window_ms <= 1000:
        raise ValueError('tetragon_window_ms must be 0..1000')
    if args.action == 'watch' and not args.tetragon and getattr(args,'tetragon_log',None):
        raise ValueError('--no-tetragon conflicts with --tetragon-log')
    if not 1 <= args.viztracer_max_functions <= 4096:
        raise ValueError("viztracer_max_functions must be 1..4096")
    paths = [getattr(args, key, None) for key in ("log", "summary", "prompt_log", "evidence_log")]
    resolved = [str(Path(path).resolve()) for path in paths if path]
    if len(resolved) != len(set(resolved)):
        raise ValueError("audit, summary, prompt and evidence logs must use separate paths")
    if args.action in {"capture", "run"}:
        if not math.isfinite(args.capture_window) or not .1 <= args.capture_window <= 30:
            raise ValueError("capture window must be 0.1..30 seconds")
    if args.action in {"capture", "run", "proxy"} and args.level != "event":
        raise ValueError("content capture requires event level")
    if args.evidence not in {"none", "runtime"}:
        raise ValueError("invalid evidence mode")
    if not math.isfinite(args.review_interval) or args.review_interval < 0 or 0 < args.review_interval < 5:
        raise ValueError("review_interval must be 0 or at least 5 seconds")
    if args.action == "review":
        if args.pid <= 0 or len(args.task_log) > 4 or len(args.output_root) > 4:
            raise ValueError("review requires a positive PID and at most four logs/output roots")
        if args.level != "event":
            raise ValueError("process review requires event level")
    if not 1 <= args.history_limit <= 100000:
        raise ValueError("history_limit must be 1..100000")
    from .classification import validate_task, DEFAULT_TASK
    args.classification = validate_task(args.classification if args.classification is not None else DEFAULT_TASK)
    if args.input_mode not in {"full","compact"}: raise ValueError("input_mode must be full or compact")
    if args.function_classification is not None:
        validate_task(args.function_classification)
        if [c['label'] for c in args.function_classification['categories']] != [c['label'] for c in args.classification['categories']]:
            raise ValueError('Function policy labels must match system policy labels and order')
    if args.ui not in {"top", "htop", "btop"}:
        raise ValueError("unknown UI profile")
    if not 1 <= args.batch_size <= 64 or args.batch_concurrency < 1:
        raise ValueError("batch_size must be 1..64 and batch_concurrency positive")
    if not math.isfinite(args.batch_wait_ms) or not 0 <= args.batch_wait_ms <= 50:
        raise ValueError("batch_wait_ms must be 0..50")
    if args.cache_policy not in {"native", "session", "isolated", "off"}:
        raise ValueError("invalid cache policy")
    for key in ("timeout", "drain_timeout", "duration", "interval", "window_ms"):
        value = getattr(args, key, None)
        if value is not None and (not math.isfinite(value) or value < 0 or
                                 value == 0):
            raise ValueError(key + " must be finite and positive")
    for key, minimum in (("workers", 1), ("capacity", 1),
                         ("log_max_bytes", 1024), ("log_backups", 0), ("max_events", 1), ("max_groups", 1)):
        value = getattr(args, key, minimum)
        if value < minimum:
            raise ValueError(key + " is below minimum")
    if getattr(args, "uid", 0) < 0:
        raise ValueError("uid cannot be negative")
    if getattr(args, "summary", None) and getattr(args, "log", None):
        if Path(args.summary).resolve() == Path(args.log).resolve():
            raise ValueError("summary and event log must use different paths")
    args.task_context = {}
    if getattr(args, "context", None):
        context = read_json(args.context, 4096)
        if set(context) - {"task_id", "window_id", "user_intent", "authorization"}:
            raise ValueError("unknown task context field")
        if any(not isinstance(v, str) or len(v) > 2048 for v in context.values()):
            raise ValueError("task context values must be short strings")
        args.task_context = context
    from .granularity import LEVELS
    if args.level not in LEVELS:
        raise ValueError("unknown inference level")
    for level, key in (("window", "window_id"), ("task", "task_id")):
        if args.level == level and not args.task_context.get(key):
            raise ValueError(level + " level requires context." + key)
    if args.action in {"check", "assess"} and args.level != "event":
        raise ValueError("check/assess are single-decision boundaries; use --level event")
    return args
