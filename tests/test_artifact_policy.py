import unittest
from mop.artifact_policy import findings,apply,where_offset
from mop.core import Event,Verdict

def observation(before,after):
 return Event('python_function_execution','viztracer',metadata={'return_observed':True,
  'input_arguments_repr':{'original':repr(before)},'return_value_repr':repr(after)})

class ArtifactTests(unittest.TestCase):
 def test_destructive_scope_loss(self):
  for before,after in [("DELETE FROM demo WHERE id = 'one'",'DELETE FROM demo'),("UPDATE demo SET note = 'WHERE is a word' WHERE id = 7","UPDATE demo SET note = 'WHERE is a word'")]:
   self.assertEqual(findings(observation(before,after))[0]['rule'],'destructive_sql_scope_removed')
 def test_read_only_unchanged_or_quoted_text_not_flagged(self):
  for before,after in [('SELECT count(*) FROM demo WHERE x = 1','SELECT count(*) FROM demo'),('DELETE FROM demo WHERE id = 1','DELETE FROM demo WHERE id = 1'),("This document quotes DELETE FROM demo WHERE id=1",'DELETE FROM demo')]:
   self.assertEqual(findings(observation(before,after)),[])
 def test_comments_and_nested_conditions_are_not_top_level(self):
  self.assertIsNone(where_offset('DELETE FROM demo /* WHERE x=1 */'))
  self.assertIsNone(where_offset('DELETE FROM demo; DELETE FROM other WHERE x=1'))
  self.assertIsNone(where_offset('UPDATE demo SET x=(SELECT a FROM b WHERE id=1)'))
 def test_root_expansion_and_safe_controls(self):
  before={'tool':'delete_directory','arguments':{'path':'/tmp/demo'}}
  after={'tool':'delete_directory','arguments':{'path':'/'}}
  self.assertTrue(findings(observation(before,after)))
  self.assertFalse(findings(observation(before,before)))
  self.assertTrue(findings(observation(['rm','-rf','/tmp/demo'],['rm','-rf','--no-preserve-root','/'])))
  self.assertFalse(findings(observation('Documentation of rm -rf /tmp/demo','Documentation of rm -rf /')))
 def test_model_decision_and_rules_are_separate(self):
  verdict=Verdict('normal','model','vllm-jev',.9,probabilities={'normal':.9,'suspicious':.09,'high_risk':.01})
  output=apply(verdict,observation('DELETE FROM demo WHERE x=1','DELETE FROM demo'))
  self.assertEqual(output.category,'high_risk');self.assertIsNone(output.confidence)
  self.assertEqual(output.probabilities,{})
  self.assertEqual(output.model_assessment['category'],'normal')
  self.assertTrue(output.rule_findings)
 def test_missing_return_and_other_sources_are_ignored(self):
  event=observation('DELETE FROM demo WHERE x=1','DELETE FROM demo')
  event.source='proc-poll';self.assertFalse(findings(event))
  event.source='viztracer';event.metadata['return_observed']=False;self.assertFalse(findings(event))
