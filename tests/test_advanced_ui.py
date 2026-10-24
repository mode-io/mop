import unittest
from mop.view_filters import compile_filter
from mop.ui_state import ViewState
from mop.ui import draw, STYLES, process_line
from mop.core import Engine
from support import FixtureProvider
from test_ui import row, Screen

class AdvancedViewTests(unittest.TestCase):

    def test_compound_filters(self):
        match = compile_filter('user:tester cpu>=5 mem<100 advice:suspicious')
        self.assertTrue(match(dict(row(1, cpu=6), _advice='suspicious')))
        self.assertFalse(match(dict(row(1, cpu=4), _advice='suspicious')))
        self.assertFalse(match(dict(row(1, cpu=6), _advice='normal')))
        self.assertTrue(compile_filter('name:"worker" pid=1')(row(1)))

    def test_invalid_filters_never_silently_match(self):
        for value in ['cpu>nan', 'cpu>hello', 'unknown:value', 'cpu>', '"unfinished']:
            state = ViewState(filter=value)
            self.assertEqual(state.visible([row(1)], []), [])
            self.assertIn('Filter error', state.filter_error)

    def test_tags_do_not_cross_reused_pids(self):
        state = ViewState()
        items = state.visible([row(1), row(2)], [])
        state.key(ord(' '), None, items)
        tagged = items[state.index]['pid']
        state.key(ord('y'), None, items)
        self.assertEqual([r['pid'] for r in state.visible([row(1), row(2)], [])], [tagged])
        self.assertEqual(state.visible([dict(row(tagged), start_ticks=2)], []), [])
        state.key(ord('U'), None, [])
        self.assertFalse(state.tags)

    def test_freeze_is_display_only_and_deep_copied(self):
        state = ViewState()
        engine = Engine(FixtureProvider())
        rows = [row(1, cpu=2)]
        state.key(ord('z'), engine, [])
        self.assertEqual(state.visible(rows, [])[0]['cpu'], 2)
        rows[0]['cpu'] = 90
        self.assertEqual(state.visible(rows + [row(2)], [])[0]['cpu'], 2)
        self.assertEqual(dict(engine.stats), {})
        state.key(ord('z'), engine, [])
        self.assertEqual(len(state.visible(rows + [row(2)], [])), 2)

    def test_idle_reset_and_interval_limits(self):
        state = ViewState()
        state.key(ord('i'), None, [])
        self.assertEqual(len(state.visible([row(1, cpu=0), row(2, cpu=1)], [])), 1)
        state.filter = 'name:missing'
        state.tagged_only = True
        state.key(ord('='), None, [])
        self.assertEqual(len(state.visible([row(1), row(2)], [])), 2)
        for _ in range(20):
            state.key(ord('+'), None, [])
        self.assertEqual(state.interval, 0.1)
        for _ in range(20):
            state.key(ord('-'), None, [])
        self.assertEqual(state.interval, 10)

    def test_all_profiles_render_advanced_status(self):
        for profile in ('top', 'htop', 'btop'):
            screen = Screen(42, 150)
            state = ViewState(profile=profile, paused=True)
            draw(screen, [row(1)], Engine(FixtureProvider()), state, {}, STYLES)
            self.assertIn('FROZEN list; monitoring live', screen.text())

    def test_classification_not_truncated_to_seven_letters(self):
        self.assertIn('suspicious', process_line(row(1), 150, 'suspicious'))
        self.assertIn('high_risk', process_line(row(1), 150, 'high_risk'))
