import asyncio
import json
import unittest
from unittest.mock import patch

from mop.classification import ClassificationProvider
from mop.command_review import CommandReview
from mop.core import Engine, Event
from support import FixtureProvider


class CommandReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_policy_for_different_commands_and_no_invented_intent(self):
        policy = ClassificationProvider("http://127.0.0.1:18936")
        questions, options = [], []
        for command in (["uname", "-sr"], ["df", "-h", "/data1"]):
            engine = await Engine(FixtureProvider()).start()
            adapter = CommandReview(engine, command, 2048)
            source = Event("task_output_window", "command-output", pid=42, tid=42,
                           metadata={"output": [{"stream": "stdout", "text": "observed output\n"}]})
            self.assertTrue(adapter.submit(source))
            await engine.close()
            record = engine.recent[0]["event"]
            self.assertEqual(record["context"], {})
            self.assertEqual(record["metadata"]["attributes"]["observed_pid"], 42)
            launch = record["metadata"]["attributes"]["launch_command"]["text"]
            self.assertEqual(json.loads(launch), command)
            event = Event(**record)
            request = policy.choice_payload(event)
            questions.append(request["question"]); options.append(request["options"])
            self.assertNotIn("user_intent", record["metadata"])
            self.assertIn("observed output", record["metadata"]["content"])
        self.assertEqual(questions[0], questions[1])
        self.assertEqual(options[0], options[1])
        self.assertEqual(questions[0], policy.instructions)
        await policy.aclose()

    async def test_budget_failure_is_visible_and_does_not_emit_normal_placeholder(self):
        engine = await Engine(FixtureProvider()).start()
        with patch("mop.command_review.tokenizer", return_value=None):
            adapter = CommandReview(engine, ["x" * 5000], 512)
        self.assertFalse(adapter.submit(Event("task_started", "command-output")))
        await engine.close()
        self.assertTrue(adapter.failed)
        self.assertEqual(engine.stats["command_review_gaps"], 1)
        self.assertFalse(engine.recent)

    async def test_runtime_deduplication_keeps_reference_and_output(self):
        engine = await Engine(FixtureProvider()).start()
        adapter = CommandReview(engine, ["uname"])
        for _ in range(2):
            adapter.submit(Event("task_output_window", "command-output", metadata={
                "runtime_evidence": {"process": {"exe": "/usr/bin/uname"}},
                "output": [{"stream": "stdout", "text": "Linux\n"}],
            }))
        await engine.close()
        metadata = [r["event"]["metadata"] for r in engine.recent]
        self.assertEqual(sum(m["kind"] == "runtime_snapshot" for m in metadata), 1)
        self.assertEqual(sum(m["kind"] == "task_output_window" for m in metadata), 2)
        self.assertEqual(len({m["attributes"]["runtime_snapshot_sha256"] for m in metadata}), 1)


if __name__ == "__main__":
    unittest.main()
