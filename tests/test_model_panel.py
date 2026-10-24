import asyncio
import copy
import curses
import tempfile
import unittest
from unittest.mock import patch,AsyncMock
from mop.core import Engine
from mop.model_panel import cards,draw,command_for
from mop.model_slots import Registry
from mop.model_commands import install_placeholder
from mop.ui import STYLES
from mop.ui_state import ViewState
from test_ui import Screen
from support import FixtureProvider

class Provider(FixtureProvider):
    def model_status(self):
        return {'models':[{'name':'openjev-core','role':'core','version':'openjev-placeholder','model':'mop-open-jev-2b','state':'active','calls':12,'unknown':0,'p95_ms':157.2}]}

class PanelTests(unittest.TestCase):
    def test_five_film_cards_and_live_metrics(self):
        screen=Screen(34,120);state=ViewState(overlay='models')
        draw(screen,Engine(Provider()),state,STYLES)
        text=screen.text()
        for name in ('jev-core','guard-privacy','guard-permission','guard-content','guard-compliance'):self.assertIn(name,text)
        self.assertIn('models loaded 1/5',text)
        self.assertIn('157ms',text)
        self.assertIn('[ install ]',text)
        self.assertNotIn('41ms',text)
        self.assertIn('OpenJev placeholder',text)
    def test_small_terminals_and_scroll(self):
        state=ViewState(overlay='models',model_index=4)
        for h,w in ((8,40),(16,60),(24,80),(34,120),(40,160)):
            screen=Screen(h,w);draw(screen,Engine(Provider()),state,STYLES)
            if h>=16:self.assertIn('guard-compliance',screen.text())
    def test_models_keys_do_not_change_process_controls(self):
        state=ViewState(overlay='models');engine=Engine(Provider())
        state.key(curses.KEY_DOWN,engine,[])
        state.key(10,engine,[])
        self.assertEqual(state.model_action,['models','install','guard-privacy'])
        self.assertIsNone(state.pending_control)
        self.assertEqual(state.sort,'cpu')
        state.key(27,engine,[])
        state.key(ord('M'),engine,[])
        self.assertEqual(state.sort,'memory')
    def test_empty_disable_does_not_install(self):
        self.assertIsNone(command_for(cards({})[1],ord('d')))
    def test_no_global_enforce_switch(self):
        state=ViewState(overlay='models');engine=Engine(Provider())
        state.key(ord('e'),engine,[])
        self.assertIn('mop gate --mode enforce',state.model_notice)
        self.assertEqual(state.model_action,[])
    def test_install_is_real_shadow_registration(self):
        with tempfile.TemporaryDirectory() as root:
            registry=Registry(root=root)
            with patch('mop.model_commands.probe',new=AsyncMock(return_value={'status':'reachable'})) as probe:
                slot=install_placeholder(registry,'guard-privacy')
                self.assertEqual(slot['state'],'shadow')
                self.assertEqual(slot['model'],registry.default['models'][0]['model'])
                self.assertEqual(len(registry.read()['models']),2)
                probe.assert_awaited_once()
    def test_probe_failure_does_not_register(self):
        with tempfile.TemporaryDirectory() as root:
            registry=Registry(root=root)
            with patch('mop.model_commands.probe',new=AsyncMock(side_effect=ValueError('Unavailable'))):
                with self.assertRaises(ValueError):install_placeholder(registry,'guard-privacy')
            self.assertEqual(len(registry.read()['models']),1)

    def test_pending_install_has_no_invented_percentage(self):
        import time
        state=ViewState(overlay='models',model_index=1,model_busy='guard-privacy',model_started=time.monotonic())
        screen=Screen(40,140);draw(screen,Engine(Provider()),state,STYLES)
        self.assertIn('checking',screen.text())
        self.assertNotIn('%',screen.text())
