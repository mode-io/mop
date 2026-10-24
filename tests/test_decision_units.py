import concurrent.futures
import json
import unittest

from mop.decision_units import DecisionBudgetError, DecisionSplitter, Observation, from_span


class DecisionUnitsTests(unittest.TestCase):
    def setUp(self):
        self.splitter = DecisionSplitter(lambda e: len(json.dumps(e.payload())), budget=1800)

    def test_lossless_unicode_and_context(self):
        original = ("Unicode: 安全 🔐\n" + "x" * 200 + "\n") * 20
        obs = Observation("test", "output", original, attributes={"resource": "fixture"})
        units = self.splitter.split(obs)
        self.assertGreater(len(units), 1)
        self.assertEqual("".join(e.metadata["content"] for e in units), original)
        for i, event in enumerate(units):
            m = event.metadata
            self.assertEqual((m["part"], m["parts"]), (i + 1, len(units)))
            self.assertEqual(m["content"], original[slice(*m["char_range"])])
            self.assertLessEqual(self.splitter.cost(event), self.splitter.budget)
        obs.attributes["resource"] = "changed"
        self.assertEqual(units[0].metadata["attributes"]["resource"], "fixture")

    def test_empty(self):
        unit, = self.splitter.split(Observation("test", "empty", ""))
        self.assertFalse(unit.metadata["fragment"])

    def test_fail_closed_bounds(self):
        with self.assertRaises(DecisionBudgetError):
            self.splitter.split(Observation("test", "output", "a", attributes={"huge": "x" * 10000}))
        with self.assertRaises(DecisionBudgetError):
            DecisionSplitter(lambda e: 1, max_bytes=3).split(Observation("test", "output", "abcd"))
        with self.assertRaises(DecisionBudgetError):
            DecisionSplitter(lambda e: len(json.dumps(e.payload())), budget=1800, max_units=1).split(
                Observation("test", "output", "x" * 10000))

    def test_parallel_operations_do_not_mix(self):
        def run(i):
            return self.splitter.split(Observation("test", "output", str(i) * 100, operation_id=str(i)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            groups = list(pool.map(run, range(100)))
        self.assertEqual(len({g[0].metadata["series_id"] for g in groups}), 100)
        for i, group in enumerate(groups):
            self.assertTrue(all(e.metadata["operation_id"] == str(i) for e in group))

    def test_span_adapter(self):
        observation = from_span({
            "context": {"trace_id": "trace", "span_id": "span"}, "parent_id": "parent",
            "name": "POST", "attributes": {"http.status_code": 200},
        })
        unit, = self.splitter.split(observation)
        self.assertEqual(unit.pid, 0)
        self.assertEqual(unit.context, {})
        self.assertEqual(unit.metadata["parent_id"], "parent")


if __name__ == "__main__":
    unittest.main()
