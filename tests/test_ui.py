import curses
import tempfile
import unittest
from pathlib import Path
from mop.core import Engine
from support import FixtureProvider
from mop.meters import cpu_percent, read_system
from mop.ui import draw, fit, STYLES
from mop.ui_state import ViewState, order_rows, identity

def row(pid, ppid=1, tid=None, name='worker', cpu=0, memory=10):
    return dict(pid=pid, tid=tid or pid, ppid=ppid, start_ticks=1, comm=name, cpu=cpu, rss_mb=memory, memory_percent=1, state='S', uid=1001, user='tester', ticks=100, vsize=104857600, priority=20, nice=0)

class Screen:

    def __init__(self, height=24, width=120):
        (self.height, self.width) = (height, width)
        self.cells = {}

    def getmaxyx(self):
        return (self.height, self.width)

    def erase(self):
        self.cells = {}

    def refresh(self):
        pass

    def addnstr(self, y, x, text, count, style=0):
        assert 0 <= y < self.height and 0 <= x < self.width
        assert x + len(text[:count]) < self.width
        for (i, c) in enumerate(text[:count]):
            self.cells[y, x + i] = (c, style)

    def text(self):
        return '\n'.join((''.join((self.cells.get((y, x), (' ', 0))[0] for x in range(self.width))) for y in range(self.height)))

class StateTests(unittest.TestCase):

    def test_tree_places_parent_before_children_and_threads(self):
        rows = [row(11, 10), row(10), row(10, tid=12)]
        result = order_rows(rows, tree=True)
        self.assertEqual([r['tid'] for r in result][0], 10)
        self.assertEqual([r['depth'] for r in result], [0, 1, 1])

    def test_tree_handles_racy_cycles_without_losing_rows(self):
        result = order_rows([row(1, 2), row(2, 1)], tree=True)
        self.assertEqual(len(result), 2)
        self.assertEqual(len({identity(r) for r in result}), 2)

    def test_cpu_and_memory_sort(self):
        rows = [row(10, cpu=80, memory=1), row(20, cpu=5, memory=100)]
        state = ViewState()
        self.assertEqual(state.visible(rows, [])[0]['pid'], 10)
        state.key(ord('M'), None, rows)
        self.assertEqual(state.visible(rows, [])[0]['pid'], 20)

    def test_selection_tracks_identity_across_sort_refresh(self):
        state = ViewState()
        rows = [row(10, cpu=80), row(20, cpu=5)]
        state.visible(rows, [])
        self.assertEqual(state.selected[0], 10)
        rows[1]['cpu'] = 90
        result = state.visible(rows, [])
        self.assertEqual(result[state.index]['pid'], 10)

    def test_page_navigation_is_clamped(self):
        state = ViewState()
        rows = [row(i) for i in range(20)]
        state.key(curses.KEY_NPAGE, None, rows, 7)
        self.assertEqual(state.index, 7)
        state.key(curses.KEY_END, None, rows)
        self.assertEqual(state.index, 19)
        state.key(curses.KEY_NPAGE, None, rows, 7)
        self.assertEqual(state.index, 19)

    def test_filter_hides_only_display_rows(self):
        state = ViewState()
        rows = [row(1, name='python'), row(2, name='bash')]
        state.key(curses.KEY_F4, None, rows)
        for c in 'python':
            state.key(ord(c), None, rows)
        state.key(10, None, rows)
        self.assertEqual(len(state.visible(rows, [])), 1)
        self.assertEqual(len(rows), 2)

    def test_search_selects_without_filtering(self):
        state = ViewState()
        rows = [row(1, name='python'), row(2, name='bash')]
        items = state.visible(rows, [])
        state.key(curses.KEY_F3, None, items)
        for c in 'bash':
            state.key(ord(c), None, items)
        state.key(10, None, items)
        result = state.visible(rows, [])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[state.index]['comm'], 'bash')

    def test_q_in_editor_does_not_quit(self):
        state = ViewState(editor='filter')
        self.assertFalse(state.key(ord('q'), None, []))
        self.assertEqual(state.filter, 'q')

    def test_f9_opens_details_not_process_control(self):
        state = ViewState()
        self.assertFalse(state.key(curses.KEY_F9, None, []))
        self.assertEqual(state.overlay, 'detail')
        self.assertFalse(state.key(27, None, []))
        self.assertEqual(state.overlay, '')

    def test_thread_and_tree_keys_are_distinct(self):
        state = ViewState()
        state.key(ord('t'), None, [])
        self.assertTrue(state.tree)
        self.assertFalse(state.threads)
        state.key(ord('H'), None, [])
        self.assertTrue(state.threads)

    def test_sort_dialog(self):
        state = ViewState()
        state.key(curses.KEY_F6, None, [])
        state.key(curses.KEY_DOWN, None, [])
        state.key(10, None, [])
        self.assertEqual(state.sort, 'memory')

    def test_empty_filter_resets_selection(self):
        state = ViewState(filter='does-not-exist', index=99, selected=(99, 99, 1))
        self.assertEqual(state.visible([row(1)], []), [])
        self.assertEqual(state.index, 0)
        self.assertIsNone(state.selected)

class MeterRenderTests(unittest.TestCase):

    def test_cpu_delta_and_warmup(self):
        previous = {'cpus': {'cpu0': (100, 40)}}
        current = {'cpus': {'cpu0': (200, 60), 'cpu1': (200, 60)}}
        result = cpu_percent(current, previous)
        self.assertEqual(result['cpu0'], 80)
        self.assertIsNone(result['cpu1'])

    def test_memory_available_and_guest_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'stat').write_text('cpu 10 0 20 30 5 0 0 0 1000 0\ncpu0 10 0 20 30 5 0 0 0 1000 0\n')
            (p / 'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 100 kB\nSwapFree: 25 kB\n')
            (p / 'loadavg').write_text('1.0 2.0 3.0 1/10 123\n')
            (p / 'uptime').write_text('3600 100\n')
            values = read_system(p)
            self.assertEqual(values['cpus']['cpu'][0], 65)
            self.assertEqual(values['memory_used'], 600 * 1024)
            self.assertEqual(values['swap_used'], 75 * 1024)

    def test_header_footer_and_selected_row(self):
        screen = Screen()
        draw(screen, [row(10)], Engine(FixtureProvider()), ViewState(), {}, STYLES)
        text = screen.text()
        self.assertIn('MOP', text)
        self.assertIn('CPU%', text)
        self.assertIn('F10Quit', text)
        self.assertTrue(any((style == STYLES['selected'] for (_, style) in screen.cells.values())))

    def test_small_terminal_and_no_color_do_not_crash(self):
        screen = Screen(8, 40)
        draw(screen, [], Engine(FixtureProvider()), ViewState(), {})
        self.assertIn('resize', screen.text())

    def test_narrow_terminal_render(self):
        screen = Screen(20, 60)
        draw(screen, [row(10)], Engine(FixtureProvider()), ViewState(), {}, STYLES)
        self.assertIn('MOP', screen.text())

    def test_escape_and_wide_text_fit(self):
        text = fit('\x1b\u5371\u9669abc', 5)
        self.assertNotIn('\x1b', text)
        self.assertEqual(text, '?\u5371\u9669')
if __name__ == '__main__':
    unittest.main()
