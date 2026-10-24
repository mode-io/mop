import json
from pathlib import Path
import sys
import tempfile
import unittest
from mop.variables import VariableTrace, describe, reviewable


class VariableTests(unittest.TestCase):
    def collect(self, source, limit=256):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'task.py'
            path.write_text(source)
            tracer = VariableTrace(path, limit)
            tracer.run()
            self.assertEqual(tracer.errors, 0)
            return tracer

    def test_transform_and_use_versions(self):
        tracer = self.collect("text='hello'\ntext=text.upper()\nsize=len(text)\n")
        steps = [e.metadata for e in tracer.events if e.metadata.get('changed_bindings')]
        self.assertEqual(steps[1]['reads_before_line']['text']['observed']['value'], 'hello')
        self.assertEqual(steps[1]['changed_bindings']['text']['observed']['value'], 'HELLO')
        self.assertNotEqual(steps[0]['changed_bindings']['text']['binding'], steps[1]['changed_bindings']['text']['binding'])
        self.assertEqual(steps[2]['call_candidates'][0]['target'], 'len')

    def test_recursion_separate_invocations(self):
        tracer = self.collect('def f(n):\n if n: return f(n-1)\n return n\nx=f(2)\n')
        calls = [e.metadata for e in tracer.events if e.metadata['function'] == 'f' and e.metadata['outcome'] == 'entered']
        self.assertEqual(len({c['invocation'] for c in calls}), 3)
        self.assertEqual(calls[1]['parent_invocation'], calls[0]['invocation'])

    def test_exception_does_not_claim_assignment(self):
        tracer = self.collect('try:\n result=1/0\nexcept ZeroDivisionError:\n handled=True\n')
        failed = [e.metadata for e in tracer.events if e.metadata['outcome'] == 'exception']
        self.assertEqual(len(failed), 1)
        self.assertNotIn('result', failed[0]['changed_bindings'])

    def test_mutation_and_delete(self):
        tracer = self.collect('items=[]\nitems.append(1)\ndel items\n')
        self.assertTrue(any(e.metadata.get('changed_bindings', {}).get('items', {}).get('observed', {}).get('length') == 1 for e in tracer.events))
        self.assertTrue(any('items' in e.metadata.get('no_longer_observed', []) for e in tracer.events))

    def test_caps_are_reported(self):
        tracer = self.collect('for i in range(100):\n x=i\n', 5)
        self.assertEqual(len(tracer.events), 5)
        self.assertGreater(tracer.dropped, 0)
        self.assertIn('omitted', describe('x' * 2049))

    def test_no_user_repr_or_iter(self):
        class Hostile:
            def __repr__(self): raise AssertionError('repr invoked')
            def __iter__(self): raise AssertionError('iter invoked')
        self.assertIn('omitted', describe(Hostile()))

    def test_redaction(self):
        self.assertNotIn('test-password', json.dumps(describe('test-password', 'password')))
        self.assertNotIn('test-password', json.dumps(describe({'password': 'test-password'})))

    def test_only_uses_are_reviewed(self):
        tracer = self.collect("path='/etc/shadow'\nsize=len(path)\n")
        selected = [e for e in tracer.events if reviewable(e)]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].metadata['call_candidates'][0]['target'], 'len')

    def test_trace_restored_on_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'task.py'
            path.write_text('raise RuntimeError("target failed")\n')
            tracer = VariableTrace(path)
            with self.assertRaises(RuntimeError): tracer.run()
            self.assertIsNone(sys.gettrace())
            self.assertEqual(tracer.frames, {})
