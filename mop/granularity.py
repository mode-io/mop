"""Bounded operation aggregation. Level changes inference units, not capture coverage."""
import asyncio
import json
import math
import time
from collections import Counter

LEVELS = ("event", "thread", "process", "window", "task", "host")


class Granularity:
    def __init__(self, emit, stats, context, level="event", window_ms=250,
                 max_events=64, max_groups=256):
        self.emit, self.stats, self.context = emit, stats, context
        self.window_ms, self.max_events, self.max_groups = window_ms, max_events, max_groups
        if not math.isfinite(window_ms) or window_ms <= 0 or max_events < 1 or max_groups < 1:
            raise ValueError("aggregation bounds must be positive")
        self.level = self.validate_level(level)
        self.groups = {}
        self.timer = None

    def validate_level(self, level):
        if level not in LEVELS:
            raise ValueError("unknown inference level")
        if level == "window" and not self.context.get("window_id"):
            raise ValueError("window level requires operator-supplied context.window_id")
        if level == "task" and not self.context.get("task_id"):
            raise ValueError("task level requires operator-supplied context.task_id")
        return level

    def available_levels(self):
        return [level for level in LEVELS
                if (level != "window" or self.context.get("window_id"))
                and (level != "task" or self.context.get("task_id"))]

    async def start(self):
        self.timer = asyncio.create_task(self._tick())

    async def _tick(self):
        while True:
            await asyncio.sleep(min(self.window_ms / 1000, .05))
            now = time.monotonic()
            for key, group in list(self.groups.items()):
                if now - group["opened"] >= self.window_ms / 1000:
                    self._flush(key, "time_window")

    def change(self, level):
        level = self.validate_level(level)
        if level == self.level:
            return
        self.flush("level_change")
        self.level = level
        self.stats["level_changes"] += 1

    def _identity(self, event):
        level = self.level
        generation = str(event.metadata.get("start_ticks", "unverified"))
        thread_generation = str(event.metadata.get("thread_start_ticks", generation))
        if level == "process" and event.pid:
            return ("process", event.source, str(event.pid), generation)
        if level == "thread" or level == "process":
            if level == "process":
                self.stats["identity_fallback_to_thread"] += 1
            if event.tid:
                return ("thread", event.source, str(event.pid), str(event.tid), thread_generation)
            self.stats["identity_fallback_to_event"] += 1
            return None
        if level in ("window", "task"):
            return (level, event.source, self.context[level + "_id"])
        if level == "host":
            # One stream/session, not an assertion that every host operation was captured.
            return ("host", event.source, "current_capture")
        return None

    def offer(self, event):
        # Preserve full kernel evidence and exec_id identity; generic group previews
        # would discard hook arguments and group unrelated PID generations.
        if event.source == "tetragon":
            self.stats["tetragon_individual_units"] += 1
            return self.emit(event, 1)
        if self.level == "event" or event.phase == "proposed":
            return self.emit(event, 1)
        key = self._identity(event)
        if key is None:
            return self.emit(event, 1)
        if key not in self.groups:
            if len(self.groups) >= self.max_groups:
                self._flush(next(iter(self.groups)), "group_capacity")
                self.stats["group_capacity_flushes"] += 1
            self.groups[key] = {
                "opened": time.monotonic(), "first": event.timestamp, "last": event.timestamp,
                "count": 0, "counts": Counter(), "samples": [], "anchor": event}
        group = self.groups[key]
        group["count"] += 1
        group["last"] = event.timestamp
        op = event.operation if event.operation in group["counts"] or len(group["counts"]) < 32 else "__other__"
        group["counts"][op] += 1
        if len(group["samples"]) < 8:
            preview = json.dumps(event.metadata, ensure_ascii=True, allow_nan=False)
            group["samples"].append({
                "id": event.id, "pid": event.pid, "tid": event.tid,
                "operation": event.operation, "comm": event.comm[:64],
                "metadata_preview": preview[:256], "metadata_truncated": len(preview) > 256})
        self.stats["events_buffered"] += 1
        if group["count"] >= self.max_events:
            return self._flush(key, "max_events")
        return True

    def _flush(self, key, reason):
        from .core import Event
        group = self.groups.pop(key)
        elapsed_ms = (time.monotonic() - group["opened"]) * 1000
        event = Event(
            "operation_batch", "mop-aggregation",
            pid=group["anchor"].pid if key[0] in ("thread", "process") else 0,
            tid=group["anchor"].tid if key[0] == "thread" else 0,
            comm=group["anchor"].comm if key[0] in ("thread", "process") else "",
            timestamp=group["first"],
            context=dict(self.context),
            metadata={"aggregation": {
                "requested_level": self.level, "effective_level": key[0],
                "group": list(key[1:]), "raw_event_count": group["count"],
                "operation_counts": dict(group["counts"]),
                "first_timestamp": group["first"], "last_timestamp": group["last"],
                "observed_window_ms": elapsed_ms,
                "flush_reason": reason, "sample_limit": 8,
                "sampled_events": group["samples"],
                "omitted_sample_count": max(0, group["count"] - len(group["samples"])),
                "decision_scope": "group summary only, not individual-event clearance"}})
        self.stats["events_buffered"] -= group["count"]
        self.stats["groups_emitted"] += 1
        return self.emit(event, group["count"], elapsed_ms)

    def flush(self, reason="shutdown"):
        for key in list(self.groups):
            self._flush(key, reason)

    async def close(self):
        if self.timer:
            self.timer.cancel()
            await asyncio.gather(self.timer, return_exceptions=True)
        self.flush()

    def summary(self):
        return {"level": self.level, "window_ms": self.window_ms,
                "max_events": self.max_events, "max_groups": self.max_groups,
                "pending_groups": len(self.groups),
                "available_levels": self.available_levels(),
                "coverage": "selected source only; level does not widen capture"}
