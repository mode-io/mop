"""Three presentation profiles over the same engine and interaction state."""
import curses
import time
import locale

from .security_view import banner, status, severity, advice_for
from . import __version__

PROFILES = ("top", "htop", "btop")


def spark(values, width=30, ceiling=None):
    values = list(values)[-max(1, width):]
    numeric = [v for v in values if v is not None]
    scale = ceiling or max(numeric or [1]) or 1
    chars = "▁▂▃▄▅▆▇█" if "UTF" in locale.getpreferredencoding(False).upper() else "._-:=+*#"
    return "".join(" " if v is None else chars[min(7, max(0, int(v / scale * 7)))] for v in values)


def page_rows(profile, height):
    if profile == "btop" and height >= 24:
        return max(1, height - (1 + (8 if height >= 30 else 7) + (8 if height >= 34 else 6)) - 5)
    return max(1, height - (10 if profile == "top" else 12))


class Canvas:
    def __init__(self, screen, palette):
        self.screen, self.palette = screen, palette
        self.height, self.width = screen.getmaxyx()
        self.unicode = "UTF" in locale.getpreferredencoding(False).upper()

    def put(self, y, x, text, style="normal", limit=None):
        from .ui import fit
        if not (0 <= y < self.height and 0 <= x < self.width):
            return
        text = fit(text, min(self.width - x - 1, limit if limit is not None else self.width))
        try:
            self.screen.addnstr(y, x, text, len(text), self.palette.get(style, 0))
        except curses.error:
            pass

    def box(self, y, x, height, width, title, style="blue"):
        if height < 3 or width < 5:
            return
        tl, tr, bl, br, horizontal, vertical = ("╭", "╮", "╰", "╯", "─", "│") if self.unicode else ("+", "+", "+", "+", "-", "|")
        self.put(y, x, tl + horizontal * (width - 2) + tr, style)
        self.put(y + height - 1, x, bl + horizontal * (width - 2) + br, style)
        for row in range(y + 1, y + height - 1):
            self.put(row, x, vertical, style)
            self.put(row, x + width - 1, vertical, style)
        self.put(y, x + 2, " " + title + " ", "title", width - 4)

    def table(self, y, x, height, width, rows, engine, state):
        from .ui import process_line
        items = state.visible(rows, engine.recent, engine.latest_advice.values())
        header = ("DECISION   PID/TID      N  INFERms  OPERATION" if state.events else
                  "    PID USER      PRI  NI    VIRT     RES S   CPU%  MEM%      TIME+ ADVICE       Command"
                  if width >= 110 else "   PID USER        RES S  CPU%  MEM%    TIME+ ADVICE       Command")
        header_style = "plain_header" if state.profile == "top" else "panel_header"
        self.put(y, x, " " * width, header_style, width)
        self.put(y, x, header, header_style, width)
        page = max(0, height - 1)
        if state.index < state.top:
            state.top = state.index
        if state.index >= state.top + max(1, page):
            state.top = state.index - max(1, page) + 1
        state.top = min(max(0, state.top), max(0, len(items) - page))
        for offset, i in enumerate(range(state.top, min(len(items), state.top + page))):
            row = items[i]
            if state.events:
                event, verdict = row["event"], row["verdict"]
                text = "%-9s %6d/%-6d %3d %8.1f  %s" % (
                    (verdict["category"]), event["pid"], event["tid"],
                    row.get("raw_event_count", 1), row["inference_ms"], event["operation"])
                style = {"high_risk": "red", "suspicious": "yellow", "unknown": "red"}.get(verdict["category"], "normal")
            else:
                advice = row.get("_advice", "-")
                text = process_line(row, width, advice)
                style = "red" if advice == "high_risk" else "yellow" if advice in ("unknown", "suspicious") else "normal"
            if i == state.index:
                self.put(y + 1 + offset, x, " " * width, "selected", width)
                style = "selected"
            self.put(y + 1 + offset, x, text, style, width)
        if not items and page:
            self.put(y + 1, x + 1, "No matching rows", "muted", width - 2)
        return items

    def footer(self, state, items, profile):
        label = ("Search: " + state.query if state.editor == "search" else
                 "Filter: " + state.filter if state.editor == "filter" else
                 "%d/%d sort:%s filter:%s | Tab events | g level | [ ] window" %
                 (state.index + 1 if items else 0, len(items), state.sort, state.filter or "-"))
        self.put(self.height - 2, 0, state.view_status() + " | " + label, "title")
        keys = ("q quit  P/M/T sort  c command  u user  k signal  r nice  H threads  ? help"
                if profile == "top" else
                "m models  : commands  1 processes  2 decisions  K signal  R nice  c command  Enter details  q quit")
        self.put(self.height - 1, 0, keys, "muted")

    def overlay(self, state, items, engine):
        from .ui import draw_overlay
        draw_overlay(self.put, state, items, engine, self.width, self.height)


def draw_top(screen, rows, engine, state, system, palette, coverage, brand="MOP"):
    from .ui import human_bytes
    c = Canvas(screen, palette)
    screen.erase()
    if c.width < 60 or c.height < 16:
        c.put(0, 0, brand + ": resize terminal to at least 60x16", "title")
        screen.refresh()
        return
    stats, gran = engine.summary(), engine.granularity.summary()
    cpu = system.get("cpu_percent", {}).get("cpu")
    cpu_label = "warming up" if cpu is None else "%.1f%% busy  %.1f%% idle" % (cpu, 100 - cpu)
    uptime = int(system.get("uptime", 0))
    marker = " | SYNTHETIC DEMO" if system.get("demo") else ""
    c.put(0, 0, "%s %s - %s up %dd %02d:%02d | SECURITY OBSERVER%s" %
          (brand, __version__, time.strftime("%H:%M:%S"), uptime // 86400, uptime // 3600 % 24,
           uptime // 60 % 60, marker), "title")
    c.put(1, 0, "Tasks: %d total, %d running | Load: %s" %
          (len({r["pid"] for r in rows}), sum(r["state"] == "R" for r in rows), system.get("load", "-")))
    c.put(2, 0, "%%Cpu(s): %s | host-wide meters / scoped process list" % cpu_label)
    c.put(3, 0, "Mem: %s / %s | Swap: %s / %s" % tuple(human_bytes(system.get(k, 0)) for k in
          ("memory_used", "memory_total", "swap_used", "swap_total")))
    c.put(4, 0, banner(stats), severity(stats))
    c.put(5, 0, "POLICY %s / %.0fms | inference p95 %.1fms | queue %d | log errors %d" %
          (gran["level"], gran["window_ms"], stats["inference_p95_ms"], stats["queue_depth"], stats.get("log_errors", 0)), "yellow")
    c.put(6, 0, "COVERAGE: %s | advice is not enforcement; '-' means no matched evidence" % coverage, "muted")
    items = c.table(7, 0, c.height - 9, c.width - 1, rows, engine, state)
    c.footer(state, items, "top")
    c.overlay(state, items, engine)
    screen.refresh()


def draw_btop(screen, rows, engine, state, system, palette, coverage):
    from .ui import human_bytes
    c = Canvas(screen, palette)
    if c.width < 80 or c.height < 24:
        return draw_top(screen, rows, engine, state, system, palette, coverage, "B-MOP compact")
    screen.erase()
    stats, gran = engine.summary(), engine.granularity.summary()
    safety = status(stats)
    marker = " | SYNTHETIC DEMO" if system.get("demo") else ""
    c.put(0, 0, "B-MOP %s | SECURITY OPERATIONS | OBSERVE / %s%s" % (__version__, stats["provider"], marker), "title")
    left = max(30, int(c.width * .38))
    right = c.width - left
    top_h = 8 if c.height >= 30 else 7
    mid_h = 8 if c.height >= 34 else 6
    middle, bottom = 1 + top_h, 1 + top_h + mid_h
    c.box(1, 0, top_h, left, "HOST / compute")
    c.box(1, left, top_h, right - 1, "GUARD / model advice", severity(stats))
    cpu = system.get("cpu_percent", {}).get("cpu")
    cpu_text = "warmup" if cpu is None else "%.1f%%" % cpu
    c.put(2, 2, "CPU " + cpu_text + "  load " + system.get("load", "-"), limit=left - 4)
    c.put(3, 2, spark(state.history["cpu"], left - 4, 100), "green", left - 4)
    c.put(4, 2, "Mem %s / %s" % (human_bytes(system.get("memory_used", 0)), human_bytes(system.get("memory_total", 0))), limit=left - 4)
    c.put(5, 2, "Swap %s / %s" % (human_bytes(system.get("swap_used", 0)), human_bytes(system.get("swap_total", 0))), limit=left - 4)
    x = left + 2
    summary_line = " ".join(k + " " + str(v) for k, v in stats.get("categories", {}).items()) or "Waiting for classifications"
    summary_line += " | unknown %d" % safety["unknown"]
    c.put(2, x, summary_line, severity(stats), right - 5)
    c.put(3, x, "UNASSESSED %d   WAITING %d" % (safety["unassessed"], safety["waiting"]), "yellow", right - 5)
    c.put(4, x, "Level %-7s  Window %.0fms  p95 %.1fms" %
          (gran["level"], gran["window_ms"], stats["inference_p95_ms"]), limit=right - 5)
    c.put(5, x, spark(state.history["latency"], right - 5) + " latency(auto)", "yellow", right - 5)
    if top_h >= 8:
        c.put(6, 2, "Host meters / scoped process list", "muted", left - 4)
        c.put(6, x, "CLASSIFICATION ONLY; NOT ENFORCED", "yellow", right - 5)
    c.box(middle, 0, mid_h, left, "PIPELINE / gaps")
    c.box(middle, left, mid_h, right - 1, "EVENTS / recent advice")
    c.put(middle + 1, 2, "Queue %d  Unassessed %d" % (stats["queue_depth"], safety["unassessed"]), "yellow", left - 4)
    c.put(middle + 2, 2, "Kernel lost %d  Parse skip %d" % (safety["kernel_loss"], safety["parse_skips"]), limit=left - 4)
    c.put(middle + 3, 2, "Log errors %d  Units %d" % (safety["log_errors"], stats.get("completed", 0)), limit=left - 4)
    if mid_h >= 8:
        c.put(middle + 4, 2, spark(state.history["waiting"], left - 4), "blue", left - 4)
        c.put(middle + 5, 2, coverage, "muted", left - 4)
    records = list(reversed(engine.recent))
    for i, rec in enumerate(records[:mid_h - 2]):
        ev, verdict = rec["event"], rec["verdict"]
        c.put(middle + 1 + i, x, "%-7s %-17s %5.1fms" %
              ((verdict["category"]), ev["operation"][:17], rec["inference_ms"]),
              "red" if verdict["category"] == "high_risk" else "yellow" if verdict["category"] in ("unknown", "suspicious") else "normal", right - 5)
    if not records:
        c.put(middle + 1, x, "No decisions yet; not a safety verdict", "muted", right - 5)
    c.box(bottom, 0, c.height - bottom - 2, c.width - 1,
          "DECISIONS / selected scope" if state.events else "PROCESSES / recent advice")
    items = c.table(bottom + 1, 1, c.height - bottom - 4, c.width - 3, rows, engine, state)
    c.footer(state, items, "btop")
    c.overlay(state, items, engine)
    screen.refresh()
