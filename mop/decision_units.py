"""Source-independent, lossless bounded decision units for observed content.

Adapters choose real operation boundaries. This module never invents business
intent, causal links, process identity, or authorization. Callers must redact
content before passing it here. A fragment is not a complete security decision.
"""
from dataclasses import dataclass, field
import hashlib
import json
import uuid

from .core import Event


class DecisionBudgetError(ValueError):
    """Evidence cannot fit; callers must report this gap, never silently drop it."""


@dataclass
class Observation:
    source: str
    kind: str
    content: str
    operation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    parent_id: str | None = None
    attributes: dict = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)


class DecisionSplitter:
    """Split one finite observation under a caller-supplied full-input cost.

    No global mutable grouping state; separate operations cannot mix. Input,
    unit count and serialized Event size are bounded. The model tokenizer and
    request template belong to the provider, not to the collector.
    """
    def __init__(self, cost, budget=1024, max_bytes=1024 * 1024, max_units=256):
        if not callable(cost) or not 256 <= budget <= 65536:
            raise ValueError("A cost callback and budget in 256..65536 are required")
        if not 1 <= max_bytes <= 16 * 1024 * 1024 or not 1 <= max_units <= 4096:
            raise ValueError("Invalid observation bounds")
        self.cost, self.budget = cost, budget
        self.max_bytes, self.max_units = max_bytes, max_units

    def split(self, observation):
        # Snapshot user-owned containers and reject non-JSON attributes.
        o = Observation(**json.loads(json.dumps(observation.__dict__, allow_nan=False)))
        if not isinstance(o.content, str) or len(o.content.encode()) > self.max_bytes:
            raise DecisionBudgetError("Observation content exceeds the input bound")
        if not all(isinstance(x, str) and 0 < len(x) <= 128
                   for x in (o.source, o.kind, o.operation_id)):
            raise ValueError("Invalid observation identity")
        if o.parent_id is not None and (not isinstance(o.parent_id, str) or len(o.parent_id) > 128):
            raise ValueError("Invalid parent identity")
        if not isinstance(o.attributes, dict) or not isinstance(o.gaps, list):
            raise ValueError("Invalid observation context")
        digest = hashlib.sha256(o.content.encode()).hexdigest()
        series = uuid.uuid4().hex

        def event(text, start, end, index, count):
            return Event("decision_unit", o.source, metadata={
                "schema": "mop.decision.v1", "series_id": series,
                "operation_id": o.operation_id, "parent_id": o.parent_id,
                "kind": o.kind, "attributes": o.attributes,
                "part": index, "parts": count, "char_range": [start, end],
                "content_sha256": digest, "content": text,
                "fragment": not (start == 0 and end == len(o.content)),
                "gaps": o.gaps,
                "scope": "Observed content only. Fragments require related parts; normal parts do not establish whole-operation safety.",
            })

        def fits(e):
            return (len(json.dumps(e.payload(), allow_nan=False)) <= 8192
                    and self.cost(e) <= self.budget)

        chunks, offset = [], 0
        # Reserve maximum counter widths while packing; exact final units are
        # validated again because token counts are not monotonic in text length.
        while offset < len(o.content) or not chunks:
            if len(chunks) >= self.max_units:
                raise DecisionBudgetError("Observation exceeds the decision-unit bound")
            remaining = len(o.content) - offset
            size = min(remaining, 4096)
            while not fits(event(o.content[offset:offset + size], offset,
                                 offset + size, self.max_units, self.max_units)):
                if size == 0:
                    raise DecisionBudgetError("Operation context cannot fit the decision budget")
                size //= 2
            if remaining and size == 0:
                raise DecisionBudgetError("No content fits after operation context")
            # Prefer an existing record boundary, without removing whitespace.
            if size < remaining:
                newline = o.content.rfind("\n", offset + size // 2, offset + size)
                if newline >= 0:
                    candidate = newline + 1 - offset
                    if fits(event(o.content[offset:offset + candidate], offset,
                                  offset + candidate, self.max_units, self.max_units)):
                        size = candidate
            chunks.append((offset, offset + size))
            offset += size
            if not remaining:
                break
        result = [event(o.content[a:b], a, b, i + 1, len(chunks))
                  for i, (a, b) in enumerate(chunks)]
        if not all(fits(e) for e in result):
            raise DecisionBudgetError("Final decision metadata exceeds the input budget")
        assert "".join(e.metadata["content"] for e in result) == o.content
        return result


def from_span(span):
    """Map an exported OTel span without inventing an OS process identity."""
    return Observation(
        source="opentelemetry", kind="span_completed",
        operation_id=span["context"]["span_id"], parent_id=span.get("parent_id"),
        attributes={"trace_id": span["context"]["trace_id"], "name": span["name"]},
        content=json.dumps({k: span.get(k) for k in
                            ("attributes", "events", "links", "status")}, ensure_ascii=False),
        gaps=["Only exported span fields are available; arbitrary function values are not captured."],
    )
