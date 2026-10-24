from __future__ import annotations

import asyncio
import copy
import json
import math
import re
import os
import time
import uuid
from collections import Counter, deque, OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from .audit import AuditLog
from .granularity import Granularity


@dataclass
class Event:
    operation: str
    source: str
    pid: int = 0
    tid: int = 0
    comm: str = ""
    phase: str = "observed"
    metadata: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)

    def payload(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("event must be an object")
        allowed = {"operation", "source", "pid", "tid", "comm", "phase", "metadata"}
        event = cls(**{k: v for k, v in value.items() if k in allowed})
        if not isinstance(event.operation, str) or not event.operation or len(event.operation) > 128:
            raise ValueError("invalid operation")
        if not isinstance(event.source, str) or len(event.source) > 128:
            raise ValueError("invalid source")
        if any(type(x) is not int or x < 0 for x in (event.pid, event.tid)):
            raise ValueError("invalid identity")
        if not isinstance(event.comm, str) or len(event.comm) > 256:
            raise ValueError("invalid comm")
        if event.phase not in {"observed", "proposed"} or not isinstance(event.metadata, dict):
            raise ValueError("invalid phase or metadata")
        if len(json.dumps(event.payload(), allow_nan=False)) > 8192:
            raise ValueError("event too large")
        return event


@dataclass
class Verdict:
    category: str
    reason: str
    provider: str
    confidence: float | None = None
    timing: dict = field(default_factory=dict)
    probabilities: dict = field(default_factory=dict)
    model_assessment: dict | None = None
    rule_findings: list = field(default_factory=list)
    guard_trace: list = field(default_factory=list)
    policy_revision: str = ""
    policy_rules: list = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.category, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", self.category):
            raise ValueError("invalid category")
        if not isinstance(self.reason, str):
            raise ValueError("invalid reason")
        self.reason = self.reason[:512]
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("invalid confidence")
            if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
                raise ValueError("invalid confidence")


class Provider(Protocol):
    name: str
    async def infer(self, event: Event) -> Verdict: ...


def percentile(values, q):
    if not values:
        return 0.0
    return sorted(values)[max(0, math.ceil(len(values) * q) - 1)]


class Engine:
    """Bounded asynchronous audit. A verdict never implies kernel enforcement."""

    def __init__(self, provider: Provider, workers=4, capacity=256, log=None,
                 context=None, log_max_bytes=10485760, log_backups=3,
                 level="event", window_ms=250, max_events=64, max_groups=256, history_limit=512):
        if workers < 1 or capacity < 1:
            raise ValueError("workers and capacity must be positive")
        self.evidence_collector = None
        self.review_interval = 0
        self.provider = provider
        self.context = dict(context or {})
        self.state = "created"
        self.session_id = uuid.uuid4().hex
        self.workers = workers
        self.queue = asyncio.Queue(capacity)
        self.stats = Counter()
        self.granularity = Granularity(self._enqueue, self.stats, self.context,
                                       level, window_ms, max_events, max_groups)
        if type(history_limit) is not int or not 1 <= history_limit <= 100000:
            raise ValueError("history_limit must be 1..100000")
        self.recent = deque(maxlen=history_limit)
        self.latest_advice = OrderedDict()
        self.live_advice_identities = None
        self.category_counts = Counter({label: 0 for label in getattr(provider, "labels", ())})
        self.inference_ms = deque(maxlen=4096)
        self.queue_ms = deque(maxlen=4096)
        self.aggregation_ms = deque(maxlen=4096)
        self.end_to_end_ms = deque(maxlen=4096)
        self.tasks = []
        self.started = time.monotonic()
        self.log = AuditLog(log, log_max_bytes, log_backups) if log else None

    async def start(self):
        if self.state != "created":
            raise RuntimeError("engine cannot be started twice")
        self.state = "running"
        self.tasks = [asyncio.create_task(self._worker()) for _ in range(self.workers)]
        await self.granularity.start()
        return self

    def submit(self, event):
        if self.state != "running":
            raise RuntimeError("engine is not accepting events")
        event = copy.deepcopy(event)
        event.context = dict(self.context)
        count = event.metadata.get('raw_event_count', 1) if event.source == 'tetragon' else 1
        if type(count) is not int or not 1 <= count <= 64: count = 1
        self.stats["raw_events_received"] += count
        if count > 1: return self._enqueue(event, count)
        return self.granularity.offer(event)

    def retain_visible_identities(self, rows):
        """Keep latest advice for the current capture snapshot; history stays separate."""
        live = {(row["pid"], row["tid"], row["start_ticks"]) for row in rows}
        live.update((row["pid"], 0, row["start_ticks"]) for row in rows)
        self.live_advice_identities = live
        expired = [key for key in self.latest_advice if key not in live]
        for key in expired:
            del self.latest_advice[key]
        self.stats["latest_advice_pruned"] += len(expired)

    def set_level(self, level):
        if self.state != "running":
            raise RuntimeError("engine is not running")
        self.granularity.change(level)

    def set_window_ms(self, value):
        if self.state != "running" or not math.isfinite(value) or value <= 0:
            raise ValueError("window must be finite and positive on a running engine")
        self.granularity.flush("window_change")
        self.granularity.window_ms = value
        self.stats["window_changes"] += 1

    def _enqueue(self, event, raw_count=1, aggregation_ms=0):
        self.stats["seen"] += 1
        try:
            self.queue.put_nowait((event, time.monotonic(), raw_count, aggregation_ms))
        except asyncio.QueueFull:
            self.stats["dropped_queue_full"] += 1
            self.stats["raw_dropped_queue_full"] += raw_count
            return False
        self.stats["accepted"] += 1
        self.stats["raw_events_enqueued"] += raw_count
        return True

    async def _worker(self):
        while True:
            event, queued, raw_count, aggregation_ms = await self.queue.get()
            begin = time.monotonic()
            inference_started = begin
            evidence_ms = 0
            self.stats["in_flight"] += 1
            try:
                self.stats["inference_attempts"] += 1
                if self.evidence_collector is not None and event.source in {"proc-poll", "proc-review"}:
                    event.metadata["runtime_evidence"] = await asyncio.to_thread(self.evidence_collector.collect, event)
                    self.stats["evidence_collected"] += 1
                if self.evidence_collector is not None and event.source == "mop-aggregation":
                    event.metadata["evidence_unavailable_reason"] = "Runtime enrichment requires individual process events; this is an aggregate."
                evidence_ms = (time.monotonic() - begin) * 1000 if self.evidence_collector is not None else 0
                inference_started = time.monotonic()
                verdict = await self.provider.infer(event)
                if not isinstance(verdict, Verdict):
                    raise ValueError("provider returned an invalid verdict")
            except Exception as error:
                # Never persist HTTP error bodies, URLs, or credentials.
                verdict = Verdict("unknown", type(error).__name__, self.provider.name)
                self.stats["errors"] += 1
            finally:
                self.stats["in_flight"] -= 1
            finished = time.monotonic()
            latency = (finished - inference_started) * 1000
            waiting = (begin - queued) * 1000
            total = (finished - queued) * 1000 + aggregation_ms
            self.aggregation_ms.append(aggregation_ms)
            self.inference_ms.append(latency)
            self.queue_ms.append(waiting)
            self.end_to_end_ms.append(total)
            self.stats["completed"] += 1
            self.stats["raw_events_in_completed_units"] += raw_count
            self.stats[verdict.category] += 1
            record = {"schema_version": 2, "session_id": self.session_id, "event": event.payload(), "verdict": asdict(verdict),
                      "inference_ms": latency, "evidence_ms": evidence_ms, "queue_ms": waiting, "aggregation_ms": aggregation_ms,
                      "raw_event_count": raw_count, "decision_scope": "group" if aggregation_ms > 0 or raw_count > 1 else "event",
                      "end_to_end_ms": total, "enforced": False}
            self.recent.append(record)
            from .security_view import record_identity
            key = record_identity(record)
            if key is not None and (self.live_advice_identities is None or key in self.live_advice_identities):
                self.latest_advice[key] = record
                self.latest_advice.move_to_end(key)
                while len(self.latest_advice) > 65536:
                    self.latest_advice.popitem(last=False)
            if verdict.category != "unknown":
                self.category_counts[verdict.category] += 1
            if self.log:
                try:
                    self.log.write_record(record)
                except (OSError, ValueError):
                    self.stats["log_errors"] += 1
            self.queue.task_done()

    def summary(self):
        return {**dict(self.stats), "schema_version": 2, "session_id": self.session_id,
                "state": self.state, "provider": self.provider.name,
                "categories": dict(self.category_counts), "history_limit": self.recent.maxlen,
                "recent_records": len(self.recent), "latest_advice_records": len(self.latest_advice),
                "granularity": self.granularity.summary(),
                "batching": self.provider.summary() if hasattr(self.provider, "summary") else None,
                "aggregation_p95_ms": percentile(self.aggregation_ms, .95),
                "queue_depth": self.queue.qsize(),
                "elapsed_seconds": time.monotonic() - self.started,
                "inference_p50_ms": percentile(self.inference_ms, .50),
                "inference_p95_ms": percentile(self.inference_ms, .95),
                "queue_p95_ms": percentile(self.queue_ms, .95),
                "end_to_end_p95_ms": percentile(self.end_to_end_ms, .95),
                "latency_window": len(self.inference_ms),
                "enforcement": "none; observational pipeline"}

    async def close(self, drain_timeout=10):
        if self.state == "closed":
            return
        self.state = "draining"
        await self.granularity.close()
        try:
            await asyncio.wait_for(self.queue.join(), drain_timeout)
        except asyncio.TimeoutError:
            self.stats["abandoned_shutdown"] = (
                self.stats["accepted"] - self.stats["completed"])
            self.stats["raw_abandoned_shutdown"] = (
                self.stats["raw_events_enqueued"] - self.stats["raw_events_in_completed_units"])
        finally:
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            if hasattr(self.provider, "aclose"):
                await self.provider.aclose()
            if self.evidence_collector is not None and hasattr(self.evidence_collector,"close"):
                self.evidence_collector.close()
            if self.log:
                self.log.close()
            self.state = "closed"
