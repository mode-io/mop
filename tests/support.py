import asyncio
import math
from mop.core import Verdict

class FixtureProvider:
    name = "test-fixture"
    labels = ("normal", "suspicious", "high_risk")
    def __init__(self, latency_ms=0, category="normal"):
        if not math.isfinite(latency_ms) or latency_ms < 0: raise ValueError("invalid fixture delay")
        self.latency_ms, self.category = latency_ms, category
    async def infer(self, event):
        await asyncio.sleep(self.latency_ms / 1000)
        return Verdict(self.category, "Test fixture", self.name)
