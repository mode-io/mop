import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mop.cli import main, parser, provider_from
from mop.config import apply_config
from mop.classification import ClassificationProvider
from mop.core import Event, Engine
from test_guard import Server

class DefaultTests(unittest.TestCase):
    def test_default_is_real_classifier_independent_of_cwd(self):
        old=os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                for profile in ('top','htop','btop'):
                    args=apply_config(parser(profile).parse_args(['watch']),['watch'])
                    self.assertEqual(args.ui,profile)
                    self.assertEqual(args.history_limit,512)
                    self.assertEqual(args.evidence,'runtime')
                    self.assertEqual(args.review_interval,30)
                    self.assertEqual(provider_from(args).name,'vllm-jev')
                    self.assertEqual(provider_from(args).labels,('normal','suspicious','high_risk'))
                    self.assertTrue(Path(args.config).is_absolute())
            finally:os.chdir(old)

    def test_bundled_defaults_match_source_defaults(self):
        root=Path(__file__).resolve().parents[1]
        self.assertEqual(json.loads((root/'config/mop.json').read_text()),json.loads((root/'mop/default.json').read_text()))

    def test_legacy_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'old.json';path.write_text('{"provider":"mock"}')
            argv=['watch','--config',str(path)]
            with self.assertRaises(ValueError):apply_config(parser().parse_args(argv),argv)

    def test_legacy_cli_options_are_not_available(self):
        for argv in (['watch','--provider','mock'],['watch','--jev-mode','noul'],['run','--enforce','--','/bin/true']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):parser().parse_args(argv)

    def test_custom_task_drives_product_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'task.json'
            path.write_text(json.dumps({'classification':{'prompt':'Classify the task.','categories':[
                {'label':'alpha','description':'First category'},{'label':'beta','description':'Second category'}]}}))
            argv=['watch','--config',str(path)]
            provider=provider_from(apply_config(parser().parse_args(argv),argv))
            self.assertEqual(provider.labels,('alpha','beta'))
            self.assertEqual(set(Engine(provider).summary()['categories']),{'alpha','beta'})

class NativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_batch_preserves_independent_states_and_categories(self):
        seed=ClassificationProvider('http://127.0.0.1')
        replies=[{'choice':seed.options[i],'probabilities':{option:(.9 if j==i else .05) for j,option in enumerate(seed.options)}} for i in (0,2)]
        with Server({'results':replies,'decision_count':2}) as server:
            provider=ClassificationProvider(server.url)
            result=await provider.infer_batch([Event('first','fixture',context={'task_id':'A'}),Event('second','fixture',context={'task_id':'B'})])
            self.assertEqual([v.category for v in result],['normal','high_risk'])
            path,body=server.requests[0]
            self.assertEqual(path,'/plugins/vllm-jev/batch')
            self.assertEqual([json.loads(r['state'])['context']['task_id'] for r in body['requests']],['A','B'])
            self.assertNotIn('decision',result[0].__dict__)

    async def test_provider_failure_is_unknown_not_fallback(self):
        with Server({'error':'unavailable'},status=503) as server:
            engine=await Engine(ClassificationProvider(server.url)).start()
            engine.submit(Event('read','fixture'));await engine.close()
            self.assertEqual(engine.recent[0]['verdict']['category'],'unknown')
            self.assertEqual(engine.stats['errors'],1)
            self.assertNotIn('review',engine.stats)
            self.assertNotIn('review',engine.category_counts)

    async def test_invalid_batch_count_and_labels_rejected(self):
        for response in ({'results':[],'decision_count':2},{'results':[{},{}],'decision_count':2}):
            with Server(response) as server:
                with self.assertRaises(ValueError):
                    await ClassificationProvider(server.url).infer_batch([Event('a','fixture'),Event('b','fixture')])

    def test_cache_scope_and_unknown_label_validation(self):
        a=ClassificationProvider('http://127.0.0.1',cache_policy='session')
        b=ClassificationProvider('http://127.0.0.1',cache_policy='session')
        self.assertNotEqual(a.choice_payload(Event('a','fixture'))['cache_salt'],b.cache_salt)
        with self.assertRaises(ValueError):
            ClassificationProvider('http://127.0.0.1',task={'prompt':'test','categories':[
                {'label':'unknown','description':'reserved'},{'label':'other','description':'other'}]})
