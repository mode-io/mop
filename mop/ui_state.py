"""Pure terminal interaction state; no process-control side effects."""
import curses
import copy
from dataclasses import dataclass, field
from collections import deque

SORTS = ("cpu", "memory", "pid", "user", "time")


def identity(row):
    return row["pid"], row["tid"], row.get("start_ticks", 0)


def order_rows(rows, sort="cpu", descending=True, tree=False):
    key = {
        "cpu": lambda r: r.get("cpu", 0),
        "memory": lambda r: r.get("rss_mb", 0),
        "pid": lambda r: r["tid"],
        "user": lambda r: r.get("user", str(r.get("uid", ""))),
        "time": lambda r: r.get("ticks", 0),
    }[sort]
    ordered = sorted(rows, key=lambda r: (key(r), r["pid"], r["tid"]), reverse=descending)
    if not tree:
        return [dict(row, depth=0) for row in ordered]
    leaders = {r["pid"]: r for r in ordered if r["pid"] == r["tid"]}
    children, roots = {}, []
    for row in ordered:
        parent = row["pid"] if row["tid"] != row["pid"] else row.get("ppid")
        if parent in leaders and parent != row["tid"]:
            children.setdefault(parent, []).append(row)
        else:
            roots.append(row)
    output, seen = [], set()
    def append(start):
        stack = [(start, 0)]
        while stack:
            row, depth = stack.pop()
            ident = identity(row)
            if ident in seen:
                continue
            seen.add(ident)
            output.append(dict(row, depth=min(depth, 12)))
            if row["tid"] == row["pid"]:
                stack.extend((child, depth + 1) for child in reversed(children.get(row["pid"], [])))
    for root in roots:
        append(root)
    # Races/cycles in sampled ancestry must not hide rows.
    for row in ordered:
        if identity(row) not in seen:
            append(row)
    return output


@dataclass
class ViewState:
    profile: str = "htop"
    history: dict = field(default_factory=lambda: {k: deque(maxlen=90) for k in ("cpu", "latency", "waiting")})
    events: bool = False
    threads: bool = False
    tree: bool = False
    sort: str = "cpu"
    descending: bool = True
    index: int = 0
    top: int = 0
    selected: object = None
    query: str = ""
    filter: str = ""
    editor: str = ""
    overlay: str = ""
    command_text: str = ""
    pending_command: str = ""
    model_index: int = 0
    model_top: int = 0
    model_hitboxes: list = field(default_factory=list)
    model_action: list = field(default_factory=list)
    model_busy: str = ""
    model_started: float = 0
    model_notice: str = ""
    model_results: dict = field(default_factory=dict)
    sort_index: int = 0
    overlay_offset: int = 0
    overlay_max: int = 0

    tags: set = field(default_factory=set)
    tagged_only: bool = False
    hide_idle: bool = False
    paused: bool = False
    frozen: dict = field(default_factory=dict)
    interval: float = 1.0
    filter_error: str = ""
    show_command: bool = False
    user_filter: str = ""
    pid_filter: set = field(default_factory=set)
    control_kind: str = ""
    control_value: str = ""
    control_target: dict = field(default_factory=dict)
    control_confirm: bool = False
    pending_control: object = None
    notice: str = ""
    cpu_values: dict = field(default_factory=dict)

    def view_status(self):
        return (self.notice + " | " if self.notice else "") + ("FROZEN list; monitoring live | " if self.paused else "") + "sample %.2fs | tags %d%s%s" % (
            self.interval, len(self.tags), " only" if self.tagged_only else "", " | active only" if self.hide_idle else "") + (" | " + self.filter_error if self.filter_error else "")

    def visible(self, rows, records, advice_records=None):
        from .security_view import advice_index, indexed_advice
        from .view_filters import compile_filter
        if self.paused:
            if self.events not in self.frozen:
                self.frozen[self.events] = copy.deepcopy((rows, list(records), list(advice_records if advice_records is not None else records)))
            rows, records, advice_records = self.frozen[self.events]
        else:
            self.frozen.clear()
        advice_records = list(advice_records if advice_records is not None else records)

        if self.events:
            items = list(reversed(records))
            label = lambda r: r["event"]["operation"] + " " + r["event"]["comm"] + " " + (r["verdict"]["category"])
            ident = lambda r: r["event"]["id"]
        else:
            items = order_rows(rows, self.sort, self.descending, self.tree)
            label = lambda r: r["comm"] + " " + r.get("user", "") + " " + str(r["tid"])
            ident = identity
        if not self.events:
            indexed = advice_index(advice_records)
            items = [dict(r, _advice=indexed_advice(r, indexed), _tagged=identity(r) in self.tags, _show_command=self.show_command) for r in items]
            if self.user_filter:
                items = [r for r in items if self.user_filter in {r.get('user'), str(r.get('uid'))}]
            if self.pid_filter:
                items = [r for r in items if r['pid'] in self.pid_filter]
            if self.hide_idle:
                items = [r for r in items if r.get("cpu", 0) > 0]
            if self.tagged_only:
                items = [r for r in items if r["_tagged"]]
        self.filter_error = ""
        if self.filter:
            try:
                predicate = compile_filter(self.filter)
                def fields(r):
                    if not self.events: return r
                    return dict(r["event"], _advice=r["verdict"]["category"])
                items = [r for r in items if predicate(fields(r))]
            except ValueError as error:
                self.filter_error = "Filter error: " + str(error)
                items = []
        if self.selected is not None:
            for i, item in enumerate(items):
                if ident(item) == self.selected:
                    self.index = i
                    break
        self.index = min(max(0, self.index), max(0, len(items) - 1))
        if items:
            self.selected = ident(items[self.index])
        else:
            self.selected = None
        return items

    def search_next(self, items, after=False):
        if not items or not self.query:
            return
        for step in range(int(after), len(items) + int(after)):
            i = (self.index + step) % len(items)
            row = items[i]
            text = (row["event"]["operation"] + " " + row["event"]["comm"]
                    if self.events else row["comm"] + " " + row.get("user", ""))
            if self.query.casefold() in text.casefold():
                self.index, self.selected = i, None
                break

    def key(self, key, engine, items, page_size=10):
        if key == -1:
            return False
        if self.overlay=='models':
            from .model_panel import handle_key
            handle_key(self,key,engine)
            return False
        if key==curses.KEY_MOUSE:
            try:_,_,_,_,buttons=curses.getmouse()
            except curses.error:return False
            if buttons & curses.BUTTON4_PRESSED:key=curses.KEY_UP
            elif buttons & getattr(curses,'BUTTON5_PRESSED',0):key=curses.KEY_DOWN
            else:return False
        if self.overlay=='command':
            if key==27:self.overlay=''
            elif key in (10,13):self.pending_command=self.command_text;self.command_text='';self.overlay=''
            elif key in (curses.KEY_BACKSPACE,127,8):self.command_text=self.command_text[:-1]
            elif 32<=key<=126:self.command_text=(self.command_text+chr(key))[:512]
            return False
        if key==ord(':') and not self.control_kind and not self.editor:
            self.overlay='command';self.command_text='';return False
        if key==ord('m') and not self.control_kind and not self.editor:
            self.overlay='models';self.overlay_offset=0;return False
        if self.control_kind:
            if key == 27:
                self.control_kind = ""; self.control_confirm = False
            elif key in (10, 13):
                if self.control_kind in {'user', 'interval'}:
                    try:
                        if self.control_kind == 'user': self.user_filter = self.control_value.strip()
                        else:
                            value = float(self.control_value)
                            if not .1 <= value <= 10: raise ValueError('Interval must be 0.1..10 seconds')
                            self.interval = value
                        self.control_kind = ""; self.selected = None
                    except ValueError as error: self.notice = str(error)
                elif not self.control_confirm:
                    try:
                        value = int(self.control_value)
                        if self.control_kind == 'signal' and value not in {1,2,9,15,18,19}: raise ValueError('Signals: 1,2,9,15,18,19')
                        if self.control_kind == 'nice' and not -20 <= value <= 19: raise ValueError('Nice: -20..19')
                        self.control_confirm = True
                    except ValueError as error: self.notice = str(error)
                else:
                    self.pending_control = (dict(self.control_target), self.control_kind, int(self.control_value))
                    self.control_kind = ""; self.control_confirm = False
            elif not self.control_confirm and key in (curses.KEY_BACKSPACE, 127, 8):
                self.control_value = self.control_value[:-1]
            elif not self.control_confirm and 32 <= key <= 126:
                self.control_value = (self.control_value + chr(key))[:64]
            return False
        if self.editor:
            attr = "query" if self.editor == "search" else "filter"
            if key in (27, 10, 13):
                self.editor = ""
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                setattr(self, attr, getattr(self, attr)[:-1])
            elif 32 <= key <= 126:
                setattr(self, attr, (getattr(self, attr) + chr(key))[:128])
            if attr == "query":
                self.search_next(items)
            else:
                self.index, self.selected = 0, None
            return False
        if self.overlay:
            if self.overlay != "sort":
                if key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE, curses.KEY_NPAGE, curses.KEY_HOME, curses.KEY_END):
                    delta = {curses.KEY_UP: -1, curses.KEY_DOWN: 1, curses.KEY_PPAGE: -page_size, curses.KEY_NPAGE: page_size}
                    self.overlay_offset = (0 if key == curses.KEY_HOME else self.overlay_max if key == curses.KEY_END
                                           else max(0, min(self.overlay_max, self.overlay_offset + delta[key])))
                    return False
            if self.overlay == "setup":
                if key == ord("g"):
                    levels = engine.granularity.available_levels()
                    engine.set_level(levels[(levels.index(engine.granularity.level) + 1) % len(levels)])
                elif key in (ord("["), ord("]")):
                    factor = .5 if key == ord("[") else 2
                    engine.set_window_ms(min(10000, max(10, engine.granularity.window_ms * factor)))
            if self.overlay == "sort":
                if key in (curses.KEY_UP, ord("k")):
                    self.sort_index = (self.sort_index - 1) % len(SORTS)
                elif key in (curses.KEY_DOWN, ord("j")):
                    self.sort_index = (self.sort_index + 1) % len(SORTS)
                elif key in (10, 13):
                    self.sort = SORTS[self.sort_index]
                    self.descending = self.sort not in ("pid", "user")
                    self.index, self.selected = 0, None
                    self.overlay = ""
                    return False
            if key in (27, ord("q"), curses.KEY_F1, curses.KEY_F2, curses.KEY_F9, 10, 13):
                self.overlay = ""
                self.overlay_offset = 0
            return False
        if self.profile == "btop" and key in (ord("m"), 27):
            self.overlay = "setup"
            return False
        if self.profile == "btop" and key in (ord("1"), ord("2")):
            self.events = key == ord("2")
            self.index, self.top, self.selected = 0, 0, None
            return False
        if key in (ord('K'), ord('R')) or (self.profile == 'top' and key in (ord('k'), ord('r'))) or (items and not self.events and key in (curses.KEY_F7,curses.KEY_F8,curses.KEY_F9)):
            if self.events or not items:
                self.notice = 'Select a process row first'
            else:
                self.control_target = dict(items[self.index])
                self.control_kind = 'signal' if key in (ord('k'), ord('K'),curses.KEY_F9) else 'nice'
                self.control_value = '15' if self.control_kind == 'signal' else str(max(-20,min(19, items[self.index].get('nice', 0) + (-1 if key==curses.KEY_F7 else 1))))
                self.control_confirm = False; self.notice = ''
            return False
        if key == ord('c'):
            self.show_command = not self.show_command
            return False
        if key == ord('u'):
            self.control_kind = 'user'; self.control_value = self.user_filter
            return False
        if self.profile == 'top' and key == ord('d'):
            self.control_kind = 'interval'; self.control_value = str(self.interval)
            return False
        if self.profile != 'btop' and key == ord('1'):
            self.overlay = 'cpus'; self.overlay_offset = 0
            return False
        if key == ord("z"):
            self.paused = not self.paused
            self.frozen.clear()
        elif key in (ord("+"), ord("-")):
            self.interval = min(10, max(.1, self.interval * (.5 if key == ord("+") else 2)))
        elif key == ord("i"):
            self.hide_idle = not self.hide_idle
        elif key == ord("y"):
            self.tagged_only = not self.tagged_only
        elif key == ord("U"):
            self.tags.clear()
        elif key == ord("="):
            self.filter, self.tagged_only, self.hide_idle = "", False, False
            self.user_filter = ''; self.pid_filter.clear()
        elif key == ord(" ") and items and not self.events:
            selected = identity(items[self.index])
            if selected in self.tags: self.tags.remove(selected)
            elif len(self.tags) < 4096: self.tags.add(selected)
        if key in (ord("q"), 27, curses.KEY_F10):
            return True
        if key in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j"), curses.KEY_PPAGE, curses.KEY_NPAGE, curses.KEY_HOME, curses.KEY_END):
            delta = {curses.KEY_UP: -1, ord("k"): -1, curses.KEY_DOWN: 1, ord("j"): 1,
                     curses.KEY_PPAGE: -page_size, curses.KEY_NPAGE: page_size}
            self.index = (0 if key == curses.KEY_HOME else len(items) - 1 if key == curses.KEY_END
                          else self.index + delta[key])
            self.index = min(max(0, self.index), max(0, len(items) - 1))
            self.selected = (items[self.index]['event']['id'] if self.events else identity(items[self.index])) if items else None
        elif key in (curses.KEY_F1, ord("?"), ord("h")):
            self.overlay = "help"
        elif key == curses.KEY_F2:
            self.overlay = "setup"
        elif key in (curses.KEY_F3, ord("/")):
            self.editor = "search"
        elif key in (curses.KEY_F4, ord("\\")):
            self.editor = "filter"
        elif key in (curses.KEY_F5, ord("t")):
            self.tree = not self.tree
            self.selected = None
        elif key in (curses.KEY_F6, ord("<"), ord(">")):
            self.overlay = "sort"
            self.sort_index = SORTS.index(self.sort)
        elif key in (curses.KEY_F7, ord("["), curses.KEY_F8, ord("]")):
            factor = .5 if key in (curses.KEY_F7, ord("[")) else 2
            engine.set_window_ms(min(10000, max(10, engine.granularity.window_ms * factor)))
        elif key in (curses.KEY_F9, ord("d"), 10, 13):
            self.overlay = "detail"
        elif key == ord("H"):
            self.threads = not self.threads
            self.selected = None
        elif key in (ord("r"), ord("p"), 9):
            self.events = not self.events if key == 9 else key == ord("r")
            self.index, self.top, self.selected = 0, 0, None
        elif key == ord("g"):
            levels = engine.granularity.available_levels()
            engine.set_level(levels[(levels.index(engine.granularity.level) + 1) % len(levels)])
        elif key == ord("n"):
            self.search_next(items, after=True)
        elif key in (ord("P"), ord("M"), ord("T")):
            self.sort = {ord("P"): "cpu", ord("M"): "memory", ord("T"): "time"}[key]
            self.descending = True
            self.selected = None
        elif key == ord("I"):
            self.descending = not self.descending
            self.selected = None
        return False
