"""Classify supplied operation descriptions; never execute them."""
import json
import sys
import time

from .audit import AuditLog
from .config import read_json
from .core import Event


def load_case(path, override_context=None):
    value = read_json(path)
    if set(value) - {"context", "operation"} or "operation" not in value:
        raise ValueError("case requires context and operation fields")
    context = override_context or value.get("context", {})
    if not isinstance(context, dict) or set(context) - {"task_id", "window_id", "user_intent", "authorization"}:
        raise ValueError("invalid operator context")
    if any(not isinstance(v, str) or len(v) > 2048 for v in context.values()):
        raise ValueError("invalid context value")
    operation = dict(value["operation"])
    operation.setdefault("source", "operator-case")
    operation.setdefault("phase", "proposed")
    event = Event.from_dict(operation)
    event.context = context
    return event


async def assess(args, provider):
    event = load_case(args.path, args.task_context)
    start = time.monotonic()
    error = None
    try:
        verdict = await provider.infer(event)
        answer = verdict.category
        code = 2 if answer == "unknown" else 0
    except Exception as failure:
        answer, code, error = "unknown", 2, type(failure).__name__
        print("classification unavailable: " + error, file=sys.stderr)
    elapsed = (time.monotonic() - start) * 1000
    report = {"event": event.payload(), "category": answer, "model_response_valid": code == 0,
              "error": error, "latency_ms": elapsed, "provider": provider.name,
              "model": getattr(provider, "model", ""), "executed": False}
    for path in (args.log, args.summary):
        if path:
            log = AuditLog(path, args.log_max_bytes, args.log_backups)
            try:
                log.write_record(report)
            finally:
                log.close()
    print(answer)
    return code
