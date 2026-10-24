import asyncio
import curses
import os
import tempfile
import unittest
from unittest.mock import patch
from mop.core import Event,Verdict,Engine
from mop.classification import ClassificationProvider
from mop.daemon import Server,request
from mop.ui_state import ViewState,identity
from mop.model_panel import handle_key,draw
from mop.ui import STYLES
from support import FixtureProvider
from test_ui import Screen,row

class BatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragments_share_bounded_rpcs_and_keep_owners(self):
        class Transport(ClassificationProvider):
            def __init__(self):
                super().__init__('http://127.0.0.1:18936')
                self.current=0;self.peak=0;self.batches=0
            def bounded_inputs(self,event):
                return [Event(event.operation,event.source,metadata={'part':i}) for i in range(5)]
            async def _infer_batch(self,events):
                self.current+=1;self.peak=max(self.peak,self.current);self.batches+=1
                try:
                    await asyncio.sleep(.01)
                    return [Verdict('high_risk' if e.operation=='danger' else 'normal','fixture',self.name) for e in events]
                finally:self.current-=1
        p=Transport()
        try:
            values=await p.infer_batch([Event(name,'fixture') for name in ('safe','danger','safe2','safe3')])
            self.assertEqual([v.category for v in values],['normal','high_risk','normal','normal'])
            self.assertTrue(all(v.timing['input_fragments']==5 for v in values))
            self.assertEqual(p.batches,3)
            self.assertEqual(p.peak,2)
        finally:await p.aclose()
    async def test_models_request_excludes_large_evidence(self):
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}):
            engine=await Engine(FixtureProvider()).start();server=Server(engine)
            await server.start()
            try:
                engine.submit(Event('read','fixture',metadata={'text':'x'*4000}));await engine.queue.join()
                snapshot=await asyncio.to_thread(request,{'op':'snapshot'})
                lightweight=await asyncio.to_thread(request,{'op':'models'})
                self.assertIn('recent',snapshot)
                self.assertNotIn('recent',lightweight)
                self.assertNotIn('latest',lightweight)
                self.assertEqual(snapshot['summary']['session_id'],lightweight['summary']['session_id'])
            finally:await server.close();await engine.close()

class NavigationTests(unittest.TestCase):
    def test_tab_home_end_and_pages(self):
        state=ViewState(overlay='models');engine=Engine(FixtureProvider())
        for key,index in ((9,1),(curses.KEY_END,4),(curses.KEY_PPAGE,1),(curses.KEY_HOME,0),(curses.KEY_BTAB,4)):
            handle_key(state,key,engine);self.assertEqual(state.model_index,index)
    def test_wheel_and_card_action_hitbox(self):
        state=ViewState(overlay='models',model_index=2);engine=Engine(FixtureProvider())
        with patch('curses.getmouse',return_value=(0,0,0,0,curses.BUTTON4_PRESSED)):
            handle_key(state,curses.KEY_MOUSE,engine)
        self.assertEqual(state.model_index,1)
        draw(Screen(40,140),engine,state,STYLES)
        index,x,y,x1,y1,action_x=state.model_hitboxes[2]
        with patch('curses.getmouse',return_value=(0,action_x+1,y+1,0,curses.BUTTON1_CLICKED)):
            handle_key(state,curses.KEY_MOUSE,engine)
        self.assertEqual(state.model_action,['models','install','guard-permission'])
    def test_process_selection_survives_cpu_resort(self):
        state=ViewState();rows=[row(10),row(20)]
        rows[0]['cpu']=10;rows[1]['cpu']=20
        visible=state.visible(rows,[])
        state.key(curses.KEY_DOWN,Engine(FixtureProvider()),visible)
        chosen=identity(visible[1])
        rows[0]['cpu']=40
        visible=state.visible(rows,[])
        self.assertEqual(identity(visible[state.index]),chosen)

class PrefixTests(unittest.TestCase):
    def test_prefix_reordering_keeps_every_fact(self):
        from mop.input_projection import project,_project
        e=Event("file_read","tetragon",pid=42,metadata={"observation":{"path":"/tmp/report"},"parent":{"arguments":"python worker.py"},"process":{"uid":1001},"timestamp":123})
        self.assertEqual(project(e),_project(e))
        self.assertEqual(project(e,mode="full"),e.payload())
        text=__import__("json").dumps(project(e))
        self.assertLess(text.index("parent"),text.index("observation"))

class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_daemon_closes_idle_ui_connection_without_hanging(self):
        from contextlib import suppress
        from mop.daemon import socket_path
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'MOP_STATE_DIR':root}):
            engine=await Engine(FixtureProvider()).start();server=Server(engine)
            await server.start()
            reader,writer=await asyncio.open_unix_connection(str(socket_path()))
            await asyncio.sleep(0)
            try:
                await asyncio.wait_for(server.close(),1)
                with suppress(ConnectionError):
                    self.assertEqual(await asyncio.wait_for(reader.read(),1),b'')
            finally:
                writer.close()
                with suppress(ConnectionError):await writer.wait_closed()
                await server.close();await engine.close()

class ViewportTests(unittest.TestCase):
    def test_up_within_visible_cards_does_not_jump_viewport(self):
        state=ViewState(overlay="models",model_index=4);engine=Engine(FixtureProvider())
        draw(Screen(24,80),engine,state,STYLES)
        self.assertEqual(state.model_top,1)
        handle_key(state,curses.KEY_UP,engine)
        draw(Screen(24,80),engine,state,STYLES)
        self.assertEqual(state.model_top,1)
        handle_key(state,curses.KEY_HOME,engine)
        draw(Screen(24,80),engine,state,STYLES)
        self.assertEqual(state.model_top,0)
