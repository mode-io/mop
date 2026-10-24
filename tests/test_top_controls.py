import curses
import os
import signal
import subprocess
import unittest
from mop.cli import parser, pid_list
from mop.process_control import apply_action, read_identity, command_line
from mop.ui_state import ViewState
from mop.ui import draw, STYLES
from mop.core import Engine
from support import FixtureProvider
from test_ui import row, Screen


class TopInteractionTests(unittest.TestCase):
    def test_controls_require_confirmation_and_escape_cancels(self):
        s=ViewState(profile='top');items=[row(123)]
        s.key(ord('k'),None,items)
        self.assertIsNone(s.pending_control)
        s.key(10,None,items)
        self.assertTrue(s.control_confirm);self.assertIsNone(s.pending_control)
        s.key(27,None,items)
        self.assertIsNone(s.pending_control)
        s.key(ord('r'),None,items);s.key(10,None,items);s.key(10,None,items)
        self.assertEqual(s.pending_control[1:],('nice',1))

    def test_top_filters_and_command_display(self):
        s=ViewState(profile='top',user_filter='tester',pid_filter={2})
        self.assertEqual([r['pid'] for r in s.visible([row(1),row(2)],[])],[2])
        s.key(ord('c'),None,[])
        self.assertTrue(s.visible([row(2)],[])[0]['_show_command'])
        s.key(ord('='),None,[])
        self.assertFalse(s.pid_filter);self.assertFalse(s.user_filter)

    def test_dialog_renders_target_and_confirmation(self):
        s=ViewState(profile='top');items=[row(123,name='owned-test')]
        s.key(ord('k'),None,items);s.key(10,None,items)
        screen=Screen(30,140);draw(screen,items,Engine(FixtureProvider()),s,{},STYLES)
        self.assertIn('Confirm process action',screen.text())
        self.assertIn('PID 123: owned-test',screen.text())

    def test_short_flags_and_compact_help(self):
        p=parser();a=p.parse_args(['watch','-b','-n','2','-d','.2','-H','-u','tester','-p','1,2'])
        self.assertEqual((a.plain,a.iterations,a.interval,a.threads,a.pids),(True,2,.2,True,[1,2]))
        watch=next(x for x in p._actions if hasattr(x,'choices') and isinstance(x.choices,dict)).choices['watch']
        self.assertNotIn('--batch-wait-ms',watch.format_help())
        p=parser(advanced=True)
        watch=next(x for x in p._actions if hasattr(x,'choices') and isinstance(x.choices,dict)).choices['watch']
        self.assertIn('--batch-wait-ms',watch.format_help())


class OwnedProcessTests(unittest.TestCase):
    def test_stale_identity_rejected_then_renice_and_signal_owned_child(self):
        child=subprocess.Popen(['sleep','30'])
        try:
            start,_=read_identity(child.pid)
            target={'pid':child.pid,'tid':child.pid,'start_ticks':start,'comm':'sleep'}
            with self.assertRaises(ValueError):apply_action(dict(target,start_ticks=start+1),'signal',15)
            self.assertIsNone(child.poll())
            value=min(19,os.getpriority(os.PRIO_PROCESS,child.pid)+1)
            apply_action(target,'nice',value)
            self.assertEqual(os.getpriority(os.PRIO_PROCESS,child.pid),value)
            self.assertEqual(command_line(target),'sleep 30')
            apply_action(target,'signal',signal.SIGTERM)
            self.assertEqual(child.wait(timeout=3),-signal.SIGTERM)
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=3)

    def test_never_controls_mop_itself(self):
        with self.assertRaises(ValueError):
            apply_action({'pid':os.getpid(),'tid':os.getpid(),'start_ticks':0},'signal',15)



class DegradedStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_kernel_service_does_not_disable_monitor(self):
        from unittest.mock import patch, AsyncMock
        from types import SimpleNamespace
        from contextlib import redirect_stdout, redirect_stderr
        import io
        from mop.cli import execute
        from mop.config import apply_config
        argv=['watch','-b','-n','1','--evidence','none']
        args=apply_config(parser().parse_args(argv),argv)
        args.tetragon=True;args.tetragon_log=None
        check=SimpleNamespace(wait=AsyncMock(return_value=1))
        stdout=io.StringIO()
        with patch('mop.cli.provider_from',return_value=FixtureProvider()), \
             patch('mop.cli.asyncio.create_subprocess_exec',AsyncMock(return_value=check)), \
             patch('mop.cli.proc_watch',AsyncMock()) as watch, \
             redirect_stdout(stdout),redirect_stderr(io.StringIO()):
            result=await execute(args)
        self.assertEqual(result,0)
        watch.assert_awaited_once()
        self.assertFalse(args.tetragon)
        self.assertIn('kernel_source_unavailable',stdout.getvalue())

if __name__=='__main__':unittest.main()
