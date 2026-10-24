"""Model view for known decision units; full audit records are never modified."""
import copy
import json
from .capture_facts import NOTES, status, collector_content, text_envelope, runtime_facts

REDACTION = "best effort; not a guarantee for arbitrary secret formats"
AUDIT = {"schema", "series_id", "operation_id", "parent_id", "char_range",
         "content_sha256"}
ATTRIBUTE_AUDIT = {"request_id", "collector_event_id", "budget_basis",
                   "runtime_snapshot_sha256", "start_ticks"}
SCOPE = "Observed content only. Fragments require related parts; normal parts do not establish whole-operation safety."


def decode(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return text


def evidence(value):
    """Only collapse the exact capture envelope, never arbitrary application keys."""
    if (not isinstance(value, dict) or not isinstance(value.get("text"), str)
            or value.get("redaction") not in (None, REDACTION)
            or set(value) - {"text", "observed_bytes", "truncated", "redaction", "omitted"}):
        return text_envelope(value)
    if value.get("truncated") or value.get("omitted"):
        return text_envelope(value)
    return value["text"]


def project_decision(full):
    m = full.get("metadata", {})
    if (full.get("operation") != "decision_unit" or m.get("schema") != "mop.decision.v1"
            or m.get("scope") != SCOPE or not isinstance(m.get("attributes"), dict)
            or not isinstance(m.get("kind"), str)
            or not isinstance(m.get("content"), str)
            or type(m.get("part")) is not int or type(m.get("parts")) is not int
            or not 1 <= m["part"] <= m["parts"]):
        return full
    m = copy.deepcopy(m)
    attributes = {k: v for k, v in m["attributes"].items() if k not in ATTRIBUTE_AUDIT | NOTES}
    command = attributes.pop("launch_command", None)
    command_text = evidence(command)
    argv = decode(command_text) if isinstance(command_text, str) else command_text
    if attributes.get("observed_tid") == attributes.get("observed_pid"):
        attributes.pop("observed_tid", None)
    if attributes.get("process") == {}:
        attributes.pop("process")
    if isinstance(attributes.get("original_request"), str):
        attributes["original_request"] = decode(attributes["original_request"])
    content = m["content"] if m.get("fragment") else decode(m["content"])
    # Collector-owned envelopes only. Never remove hashes or fields from HTTP
    # bodies, runtime facts, user prompts, or partial fragments.
    if full["source"] == "command-review" and isinstance(content, dict) and m["kind"] != "runtime_snapshot":
        content = copy.deepcopy(content)
        launch = content.get("command")
        if launch is not None and evidence(launch) == command_text:
            content.pop("command")
        for key in ("start_ticks", "window_sequence"):
            content.pop(key, None)
        output = content.get("output")
        if isinstance(output, list):
            cleaned = []
            for item in output:
                if not isinstance(item, dict):
                    cleaned.append(item); continue
                part = dict(item)
                stream = part.pop("stream", None)
                compact = evidence(part)
                cleaned.append({"stream": stream, "text": compact} if isinstance(compact, str) else item)
            content["output"] = cleaned
    if full["source"] == "command-review" and isinstance(content, dict):
        content = runtime_facts(content) if m["kind"] == "runtime_snapshot" else collector_content(content, m["kind"])
    result = {
        "format": "mop.decision.v3",
        "context": copy.deepcopy(full.get("context", {})),
        "source": full["source"], "phase": full["phase"], "kind": m["kind"],
        "evidence": content,
    }
    if command is not None:
        result["command"] = argv
    if attributes:
        result["attributes"] = attributes
    if m.get("fragment") or m["parts"] > 1:
        result["fragment"] = {"part": m["part"], "parts": m["parts"]}
    flags = status(m.get("gaps"))
    if full["source"] == "command-review" and isinstance(content, dict) and isinstance(content.get("capture_status_flags"), dict):
        flags.update(content.pop("capture_status_flags"))
    if flags:
        result["capture_status"] = flags
    consumed = AUDIT | {"attributes", "kind", "content", "part", "parts", "fragment", "gaps", "scope"}
    extra = {k: v for k, v in m.items() if k not in consumed}
    if extra:
        result["extra"] = extra
    for k in ("pid", "tid", "comm"):
        if full.get(k):
            result[k] = full[k]
    if len(json.dumps(result, ensure_ascii=False)) >= len(json.dumps(full, ensure_ascii=False)):
        return full
    return result
