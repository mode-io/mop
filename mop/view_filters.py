"""Bounded display-only filter expressions; no eval or regular-expression input."""
import shlex
import re
import math


def compile_filter(expression):
    terms = shlex.split(expression)
    predicates = []
    for term in terms:
        match = re.fullmatch(r"(cpu|mem|pid|tid)(>=|<=|!=|=|>|<)(.+)", term, re.I)
        if match:
            key, op, raw = match.groups()
            try:
                value = float(raw)
            except ValueError:
                raise ValueError("Numeric filter requires a number") from None
            if not math.isfinite(value):
                raise ValueError("Numeric filter must be finite")
            def numeric(row, key=key.lower(), op=op, value=value):
                actual = row.get({"cpu": "cpu", "mem": "rss_mb", "pid": "pid", "tid": "tid"}[key])
                if actual is None: return False
                return {">": actual > value, "<": actual < value, ">=": actual >= value,
                        "<=": actual <= value, "=": actual == value, "!=": actual != value}[op]
            predicates.append(numeric)
        elif ":" in term:
            key, value = term.split(":", 1)
            if key not in {"user", "state", "advice", "name", "operation"} or not value:
                raise ValueError("Use user:, state:, advice:, name: or operation:")
            def field(row, key=key, value=value.casefold()):
                actual = str(row.get({"name": "comm", "advice": "_advice"}.get(key, key), "")).casefold()
                return value in actual if key in {"name", "operation"} else value == actual
            predicates.append(field)
        else:
            if any(char in term for char in "<>="):
                raise ValueError("Numeric fields: cpu, mem (MiB), pid, tid")
            predicates.append(lambda row, value=term.casefold(): value in " ".join(str(row.get(k, "")) for k in ("comm", "command_line", "user", "pid", "tid", "_advice", "operation")).casefold())
    return lambda row: all(predicate(row) for predicate in predicates)
