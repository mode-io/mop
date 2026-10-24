"""Shared, factual security presentation; never infer safety from absent alerts."""
def status(stats):
    return {
        "unknown": stats.get("unknown", 0),
        "unassessed": stats.get("raw_dropped_queue_full", 0) + stats.get("raw_abandoned_shutdown", 0),
        "waiting": max(0, stats.get("raw_events_received", 0) - stats.get("raw_events_in_completed_units", 0)
            - stats.get("raw_dropped_queue_full", 0) - stats.get("raw_abandoned_shutdown", 0)),
        "kernel_loss": stats.get("kernel_events_lost", 0),
        "parse_skips": stats.get("trace_parser_skipped", 0),
        "log_errors": stats.get("log_errors", 0),
    }


def banner(stats):
    s = status(stats)
    counts = " ".join(label + " " + str(count) for label, count in stats.get("categories", {}).items())
    return "CLASSIFICATION | " + (counts or "waiting for results") + " | unknown %d unassessed %d waiting %d" % (s["unknown"], s["unassessed"], s["waiting"])


def advice_for(row, records):
    """Show only identity-matched recent evidence, never a name/PID-only safety badge."""
    for record in reversed(records):
        event = record["event"]
        if event["pid"] != row["pid"]:
            continue
        generation = event.get("metadata", {}).get("thread_start_ticks") if event.get("tid") and event.get("tid") != event.get("pid") else None
        generation = generation if generation is not None else event.get("metadata", {}).get("start_ticks")
        if generation is None and record.get("decision_scope") == "group" and event.get("source") == "mop-aggregation":
            aggregation = event.get("metadata", {}).get("aggregation", {})
            group = aggregation.get("group")
            if aggregation.get("effective_level") in ("thread", "process") and isinstance(group, list) and group:
                try:
                    generation = int(group[-1])
                except (TypeError, ValueError):
                    pass
        if generation is None or generation != row.get("start_ticks"):
            continue
        if event.get("tid") and event["tid"] != row["tid"]:
            continue
        if record.get("decision_scope") == "group":
            return "group"
        return record["verdict"]["category"]
    return "-"


def severity(stats):
    s = status(stats)
    if stats.get("categories", {}).get("high_risk") or s["unassessed"] or s["kernel_loss"] or s["log_errors"]:
        return "red"
    if s["unknown"] or stats.get("categories", {}).get("suspicious"):
        return "yellow"
    return "title"


def record_identity(record):
    event = record["event"]
    generation = event.get("metadata", {}).get("thread_start_ticks") if event.get("tid") and event.get("tid") != event.get("pid") else None
    generation = generation if generation is not None else event.get("metadata", {}).get("start_ticks")
    if generation is None and record.get("decision_scope") == "group" and event.get("source") == "mop-aggregation":
        aggregation = event.get("metadata", {}).get("aggregation", {})
        group = aggregation.get("group")
        if aggregation.get("effective_level") in ("thread", "process") and isinstance(group, list) and group:
            try: generation = int(group[-1])
            except (TypeError, ValueError): pass
    if type(generation) is not int:
        return None
    return event["pid"], event.get("tid", 0), generation


def advice_index(records):
    result = {}
    for position, record in enumerate(records):
        key = record_identity(record)
        if key is not None:
            result[key] = (position, "group" if record.get("decision_scope") == "group" else
                           record["verdict"]["category"])
    return result


def indexed_advice(row, index):
    exact = index.get((row["pid"], row["tid"], row.get("start_ticks")), (-1, "-"))
    wildcard = index.get((row["pid"], 0, row.get("start_ticks")), (-1, "-"))
    return max(exact, wildcard, key=lambda item: item[0])[1]
