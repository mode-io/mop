"""Command-independent review of captured facts using the configured safety policy.

No command-name dispatch, generated business question, expected answer, or
operator intent is used. All commands use the same provider and categories.
"""
import copy
import json
import sys
import uuid

from .content import command_arguments
from .decision_units import DecisionBudgetError, DecisionSplitter, Observation
from .model_budget import tokenizer
from .capture_facts import collector_content, runtime_facts


class CommandReview:
    """Adapt collector events to bounded decisions while retaining launch context."""
    def __init__(self, engine, command, budget=2048):
        if not 512 <= budget <= 4096:
            raise ValueError("Decision budget must be in 512..4096")
        self.engine = engine
        self.command = command_arguments(command)
        self.operation_id = uuid.uuid4().hex
        self.provider = getattr(engine.provider, "transport", engine.provider)
        self.tokenizer = tokenizer()
        self.budget = budget
        self.splitter = DecisionSplitter(self.cost, budget=budget)
        self.runtime_seen = set()
        self.failed = False

    def __getattr__(self, key):
        return getattr(self.engine, key)

    def cost(self, event):
        event.context = dict(self.engine.context)
        if hasattr(self.provider, "choice_payload"):
            payload = self.provider.choice_payload(event)
            if self.tokenizer:
                return sum(len(self.tokenizer.encode(s, add_special_tokens=False).ids)
                           for s in [payload["state"], payload["question"], *payload["options"]]) + 256
        else:
            payload = event.payload()
        return len(json.dumps(payload, ensure_ascii=False).encode()) + 128

    def submit(self, event):
        # Preserve function-specific observation/rules when used by capture.
        if event.source != "command-output":
            return self.engine.submit(event)
        data = copy.deepcopy(event.metadata)
        runtime = data.pop("runtime_evidence", None)
        attributes = {
            "launch_command": self.command,
            "observed_pid": event.pid,
            "observed_tid": event.tid,
            "comm": event.comm,
            "start_ticks": data.get("start_ticks"),
            "collector_event_id": event.id,
            "budget_basis": "tokenizer_plus_256_reserve" if self.tokenizer else "utf8_bytes",
        }
        # Keep actual executable/cwd identity next to every output fragment.
        if runtime and isinstance(runtime, dict):
            process = runtime.get("process", {})
            if isinstance(process, dict):
                attributes["process"] = {key: process[key] for key in
                                         ("name", "exe", "cwd", "ppid") if key in process}
        observations = []
        if runtime is not None:
            import hashlib
            encoded = json.dumps(runtime, ensure_ascii=False, sort_keys=True)
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            attributes["runtime_snapshot_sha256"] = digest
            if digest not in self.runtime_seen:
                observations.append(("runtime_snapshot", json.dumps(runtime_facts(runtime), ensure_ascii=False, indent=2)))
        observations.append((event.operation, json.dumps(collector_content(data, event.operation), ensure_ascii=False, indent=2)))
        units = []
        try:
            for kind, content in observations:
                observation = Observation(
                    source="command-review", kind=kind, content=content,
                    operation_id=self.operation_id, parent_id=event.id,
                    attributes=attributes,
                    gaps=["Stdin and arbitrary process memory are not captured.",
                          "Output statements are not proof of execution.",
                          "Pipe capture may change terminal behavior; this is observation, not enforcement."],
                )
                units.extend(self.splitter.split(observation))
        except (DecisionBudgetError, ValueError) as error:
            self.failed = True
            self.engine.stats["command_review_gaps"] += 1
            self.engine.stats["log_errors"] += 1
            print("MOP review gap: " + str(error), file=sys.stderr)
            return False
        accepted = True
        for unit in units:
            if not self.engine.submit(unit):
                self.failed = True
                self.engine.stats["command_review_unsubmitted"] += 1
                accepted = False
            else:
                self.engine.stats["command_review_units"] += 1
        if runtime is not None and accepted:
            self.runtime_seen.add(digest)
            # Bound per-command bookkeeping for long-running tasks.
            if len(self.runtime_seen) > 128:
                self.runtime_seen.clear()
        return accepted

    def print_results(self):
        rows = [r for r in self.engine.recent if
                r["event"]["metadata"].get("operation_id") == self.operation_id]
        rows.sort(key=lambda row: row["event"]["timestamp"])
        for row in rows:
            m = row["event"]["metadata"]
            print("MOP %s %s/%s: %s" % (
                m["kind"], m["part"], m["parts"], row["verdict"]["category"]), file=sys.stderr)
        if self.failed:
            print("MOP review incomplete: some evidence was not submitted.", file=sys.stderr)
        print("MOP review history: %d retained units; %d submitted. Labels apply only to observed evidence."
              % (len(rows), self.engine.stats["command_review_units"]), file=sys.stderr)
