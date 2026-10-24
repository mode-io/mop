"""Controlled stdout/stderr capture example; no external services or file writes."""
import json
import sys
import time
values = [12, 18, 7]
print(json.dumps({"task": "sample_report", "rows": len(values), "total": sum(values)}), flush=True)
print("Validation passed: all three values are nonnegative.", file=sys.stderr, flush=True)
time.sleep(0.3)
