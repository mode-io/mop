import unittest
from mop.capture_facts import collector_content, status
from mop.core import Event
from mop.input_projection import project


class CaptureFactsTests(unittest.TestCase):
    def test_collector_prose_removed_but_application_text_unchanged(self):
        text = "Output statements are not proof of execution.\n"
        value = {"scope":"collector explanation", "stdin":"Inherited by the task; input bytes are not captured.",
                 "output":[{"stream":"stdout","text":text,"observed_bytes":len(text),"truncated":False,
                            "redaction":"best effort; not a guarantee for arbitrary secret formats"}]}
        result=collector_content(value,"task_output_window")
        self.assertNotIn("scope",result)
        self.assertNotIn("stdin",result)
        self.assertEqual(result["output"][0]["text"],text)
        self.assertNotIn("redaction",result["output"][0])
        self.assertFalse(result["capture_status_flags"]["stdin_captured"])

    def test_unavailability_and_omissions_remain_explicit(self):
        self.assertEqual(collector_content({"unavailable":"Process exited or evidence inaccessible"},
                                          "runtime_snapshot"),{"capture_status":"unavailable"})
        result=collector_content({"output":[{"stream":"stdout","text":"",
                                             "omitted":"overlong line omitted (9999 bytes)"}]},
                                 "task_output_window")
        self.assertEqual(result["output"][0]["omitted_bytes"],9999)
        self.assertTrue(result["output"][0]["omitted"])
        self.assertEqual(status(["new collector gap"]),{"other_gap_count":1})

    def test_process_evidence_keeps_facts_and_replaces_collector_notes(self):
        event=Event("process_review","proc-review",metadata={"runtime_evidence":{
            "scope":"collector explanation","gaps":["argv: disabled"],
            "status":{"Uid":"1001","CapEff":"0000000000000000"},
            "logs":[{"text":"Scope: business output must stay unchanged",
                     "redaction":"best effort; not a guarantee for arbitrary secret formats"}]}})
        view=project(event)["metadata"]["runtime_evidence"]
        self.assertNotIn("scope",view)
        self.assertNotIn("gaps",view)
        self.assertFalse(view["capture_status_flags"]["argv_captured"])
        self.assertEqual(view["status"],event.metadata["runtime_evidence"]["status"])
        self.assertEqual(view["logs"][0]["text"],event.metadata["runtime_evidence"]["logs"][0]["text"])

    def test_kernel_outcome_is_preserved(self):
        event=Event("process_kprobe","tetragon",metadata={
            "scope":"Selected Tetragon policies and adapter UID filter; not all syscalls or program contents.",
            "limitations":["Hook entry does not prove operation success."],
            "return_value":-13,"path":"/etc/shadow"})
        metadata=project(event)["metadata"]
        self.assertNotIn("limitations",metadata)
        self.assertEqual(metadata["return_value"],-13)
        self.assertEqual(metadata["path"],"/etc/shadow")


if __name__=="__main__":unittest.main()
