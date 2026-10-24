import asyncio
import copy
import unittest
from mop.classification import ClassificationProvider, DEFAULT_TASK, validate_task
from mop.core import Engine, Event, Verdict
from mop.security_view import advice_for, banner
from mop.cli import parser
from mop.config import apply_config

class ClassificationTests(unittest.TestCase):

    def test_custom_task_payload_and_decode(self):
        task = {'prompt': 'Classify as alpha or beta', 'categories': [{'label': 'alpha', 'description': 'First kind'}, {'label': 'beta', 'description': 'Second kind'}]}
        provider = ClassificationProvider('http://127.0.0.1:18936', task=task)
        payload = provider.choice_payload(Event('task_discovered', 'test'))
        self.assertEqual(payload['question'], task['prompt'])
        self.assertEqual(payload['options'], ['alpha: First kind', 'beta: Second kind'])
        verdict = provider._decode({'choice': provider.options[1], 'probabilities': dict(zip(provider.options, [0.1, 0.9]))})
        self.assertEqual(verdict.category, 'beta')
        self.assertEqual(verdict.probabilities, {'alpha': 0.1, 'beta': 0.9})

    def test_bad_tasks(self):
        for change in [{'prompt': ''}, {'categories': []}, {'categories': [DEFAULT_TASK['categories'][0]] * 2}]:
            task = copy.deepcopy(DEFAULT_TASK)
            task.update(change)
            with self.assertRaises(ValueError):
                validate_task(task)

    def test_invalid_responses(self):
        provider = ClassificationProvider('http://127.0.0.1:18936')
        for values in [[float('nan'), 0.3, 0.7], [0.1, 0.2, 0.2], [0.1, 0.8, 0.1]]:
            with self.assertRaises(ValueError):
                provider._decode({'choice': provider.options[0], 'probabilities': dict(zip(provider.options, values))})
        with self.assertRaises(ValueError):
            provider._decode({'choice': 'invented', 'probabilities': {}})

    def test_classification_summary(self):
        self.assertIn('normal 2', banner({'provider': 'jev-classify', 'categories': {'normal': 2}}))

class RetentionTests(unittest.IsolatedAsyncioTestCase):

    async def test_live_advice_survives_history_eviction_and_pid_reuse(self):

        class Provider:
            name = 'jev-classify'

            async def infer(self, event):
                return Verdict('normal', 'test', self.name)
        engine = await Engine(Provider(), workers=1, capacity=256, history_limit=2).start()
        for pid in range(110):
            engine.submit(Event('task_discovered', 'test', pid=pid, tid=pid, metadata={'start_ticks': 9}))
        await engine.queue.join()
        self.assertEqual(len(engine.recent), 2)
        self.assertEqual(advice_for({'pid': 1, 'tid': 1, 'start_ticks': 9}, engine.latest_advice.values()), 'normal')
        self.assertEqual(advice_for({'pid': 1, 'tid': 1, 'start_ticks': 10}, engine.latest_advice.values()), '-')
        self.assertEqual(advice_for({'pid': 1, 'tid': 2, 'start_ticks': 9}, engine.latest_advice.values()), '-')
        await engine.close()
