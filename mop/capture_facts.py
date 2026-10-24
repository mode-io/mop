"""Normalize collector-owned status messages; never rewrite application text."""
import copy
import re

NOTES = {
    "scope", "limitations", "interpretation", "request_interpretation",
    "process_attribution", "budget_basis",
}
UNAVAILABLE = {
    "Process exited or evidence inaccessible": "unavailable",
    "Runtime evidence disabled": "disabled",
    "No runtime sample yet": "not_sampled",
}


def status(gaps):
    result = {}
    for gap in gaps or []:
        if gap == "Stdin and arbitrary process memory are not captured.":
            result.update(stdin_captured=False, process_memory_captured=False)
        elif gap.startswith("Pipe capture may change terminal behavior"):
            result["stdout_stderr_transport"] = "pipe"
        elif gap.startswith("Observation after transport;") or gap.startswith("Finite post-capture review;"):
            result["inline_enforcement"] = False
        elif gap.startswith("Transport incomplete;"):
            result["transport_complete"] = False
        elif gap.startswith("Business function arguments, locals"):
            result["function_values_captured"] = False
        elif gap.startswith("HTTP request and response bodies are not captured"):
            result["http_bodies_captured"] = False
        elif gap.startswith("SQL bound parameter values"):
            result["sql_values_captured"] = False
        elif gap == "argv: disabled":
            result["argv_captured"] = False
        elif gap.startswith("stdout/stderr tails: disabled"):
            result["output_tails_captured"] = False
        elif gap == "No prior runtime sample for change comparison.":
            result["prior_sample_available"] = False
        elif gap == "Pipes, sockets and terminal output are not consumed.":
            result["pipe_socket_terminal_content_captured"] = False
        elif gap in {"Output statements are not proof of execution.",
                     "No authorization or dataflow relationship is inferred.",
                     "Redaction is best effort; evidence is untrusted."}:
            continue
        else:
            result["other_gap_count"] = result.get("other_gap_count", 0) + 1
    return result


def text_envelope(value):
    value = copy.deepcopy(value)
    if not isinstance(value, dict):
        return value
    value.pop("redaction", None)
    omitted = value.get("omitted")
    if isinstance(omitted, str):
        match = re.fullmatch(r"overlong line omitted \((\d+) bytes\)", omitted)
        if match:
            value["omitted"] = True
            value["omitted_bytes"] = int(match[1])
            value["reason"] = "line_limit"
        elif omitted == "binary content":
            value["omitted"] = True
            value["reason"] = "binary"
    return value


def collector_content(value, kind):
    """Only call on known command collector metadata, not HTTP body dictionaries."""
    if not isinstance(value, dict):
        return value
    result = copy.deepcopy(value)
    for key in NOTES:
        result.pop(key, None)
    gaps = result.pop("gaps", None)
    flags = status(gaps)
    if result.get("unavailable") in UNAVAILABLE:
        result["capture_status"] = UNAVAILABLE[result.pop("unavailable")]
    if "stdin" in result:
        result.pop("stdin")
        flags["stdin_captured"] = False
        flags["stdin_transport"] = "inherited"
    if "ordering" in result:
        result.pop("ordering")
        flags["cross_stream_order"] = "approximate"
    if "capture" in result and isinstance(result["capture"], str):
        result.pop("capture")
        flags.update(stdin_captured=False,
                     process_memory_captured=False, syscalls_captured=False)
    if isinstance(result.get("command"), dict):
        result["command"] = text_envelope(result["command"])
    if isinstance(result.get("output"), list):
        result["output"] = [text_envelope(part) for part in result["output"]]
    if flags:
        result["capture_status_flags"] = flags
    return result


def runtime_facts(value):
    """Normalize the collector's procfs structure, keeping captured text opaque."""
    if isinstance(value, list):
        return [runtime_facts(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = collector_content(value, "runtime_snapshot")
    result.pop("redaction", None)
    for key, item in list(result.items()):
        # These contain application-owned values, not collector annotations.
        if key in {"text", "values", "original_request", "request_body", "response_body"}:
            continue
        if isinstance(item, (dict, list)):
            result[key] = runtime_facts(item)
    return result
