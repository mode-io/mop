import copy
import json
import unittest
from mop.core import Event
from mop.decision_units import Observation, DecisionSplitter
from mop.input_projection import project


class DecisionProjectionTests(unittest.TestCase):
    def event(self, content, source="command-review", kind="task_output_window"):
        command={"text":'["df", "-h"]',"observed_bytes":12,"truncated":False,
                 "redaction":"best effort; not a guarantee for arbitrary secret formats"}
        obs=Observation(source,kind,json.dumps(content),attributes={
            "launch_command":command,"observed_pid":42,"observed_tid":42,
            "runtime_snapshot_sha256":"a"*64,"collector_event_id":"b"*32})
        return DecisionSplitter(lambda e:1).split(obs)[0]

    def test_audit_unchanged_and_output_exact(self):
        e=self.event({"output":[{"stream":"stdout","text":"disk 99%\n",
                    "observed_bytes":9,"truncated":False,
                    "redaction":"best effort; not a guarantee for arbitrary secret formats"}]})
        original=copy.deepcopy(e.payload())
        p=project(e)
        self.assertEqual(e.payload(),original)
        self.assertEqual(p["format"],"mop.decision.v3")
        self.assertEqual(p["command"],["df","-h"])
        self.assertEqual(p["evidence"]["output"],[{"stream":"stdout","text":"disk 99%\n"}])
        self.assertNotIn("runtime_snapshot_sha256",p["attributes"])
        self.assertEqual(project(e,"full"),original)

    def test_real_evidence_hashes_and_unknown_facts_preserved(self):
        evidence={"exe_sha256":"f"*64,"CapEff":"0000000000000001",
                  "failed":True,"path":"/etc/shadow","omitted":3}
        e=self.event(evidence,kind="runtime_snapshot")
        e.metadata["unknown_fact"]={"x":1}
        p=project(e)
        self.assertEqual(p["evidence"],evidence)
        self.assertEqual(p["extra"]["unknown_fact"],{"x":1})

    def test_partial_text_and_capture_omissions_preserved(self):
        e=self.event({"output":[{"stream":"stderr","text":"partial","truncated":True,
                    "observed_bytes":1000,
                    "redaction":"best effort; not a guarantee for arbitrary secret formats"}]})
        p=project(e)
        self.assertTrue(p["evidence"]["output"][0]["truncated"])
        e.metadata["fragment"]=True;e.metadata["parts"]=2
        p=project(e)
        self.assertEqual(p["evidence"],e.metadata["content"])
        self.assertEqual(p["fragment"],{"part":1,"parts":2})

    def test_http_original_prompt_and_payload_fields_preserved(self):
        body={"content_sha256":"business value","password":"already redacted"}
        e=self.event(body,source="http-proxy",kind="response")
        e.metadata["attributes"]["original_request"]=json.dumps({"messages":[{"content":"original prompt"}]})
        p=project(e)
        self.assertEqual(p["evidence"],body)
        self.assertEqual(p["attributes"]["original_request"]["messages"][0]["content"],"original prompt")

    def test_unknown_schema_fallback(self):
        e=self.event({"text":"hello"})
        e.metadata["schema"]="future"
        self.assertEqual(project(e),e.payload())


if __name__=="__main__":unittest.main()
