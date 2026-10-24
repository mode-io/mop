from .paths import python_command
"""htop-inspired curses interface, independently implemented for MOP."""
import asyncio
import curses
import os
import json
import textwrap
import time
import unicodedata

from .core import Event
from .meters import read_system, cpu_percent
from .proc import snapshot
from .ui_state import ViewState, SORTS, identity
from .security_view import banner, severity, advice_for
from . import __version__

STYLES = {"normal": 0, "title": 1, "green": 2, "yellow": 3, "red": 4,
          "blue": 5, "header": 6, "selected": 7, "key": 8, "muted": 9,
          "plain_header": 10, "panel_header": 11}

from .model_panel import THEME as MODEL_THEME
STYLES.update({row[0]:12+i for i,row in enumerate(MODEL_THEME)})


def safe(value):
    return "".join(c if c.isprintable() and c != "\x1b" else "?" for c in str(value))


def fit(text, width):
    result, cells = [], 0
    for c in safe(text):
        size = 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
        if cells + size > max(0, width):
            break
        result.append(c)
        cells += size
    return "".join(result)


def initialize(screen):
    screen.nodelay(True)
    if hasattr(screen, "keypad"):
        screen.keypad(True)
    try:
        curses.set_escdelay(25)
        curses.mousemask(curses.BUTTON1_CLICKED | curses.BUTTON4_PRESSED | getattr(curses,'BUTTON5_PRESSED',0))
    except (curses.error,AttributeError):pass
    palette = dict.fromkeys(STYLES, 0)
    try:
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        pairs = [(curses.COLOR_CYAN, -1), (curses.COLOR_GREEN, -1),
                 (curses.COLOR_YELLOW, -1), (curses.COLOR_RED, -1),
                 (curses.COLOR_BLUE, -1), (curses.COLOR_BLACK, curses.COLOR_GREEN),
                 (curses.COLOR_BLACK, curses.COLOR_CYAN),
                 (curses.COLOR_WHITE, curses.COLOR_BLUE), (curses.COLOR_WHITE, -1),
                 (curses.COLOR_BLACK, curses.COLOR_WHITE), (curses.COLOR_CYAN, -1)]
        for index, colors in enumerate(pairs, 1):
            curses.init_pair(index, *colors)
        for offset,(name,fg,bg,fg256,bg256) in enumerate(MODEL_THEME):
            index=12+offset
            if curses.COLORS>=256:
                colors=[fg256,bg256]
                if curses.can_change_color():
                    for side,rgb in enumerate((fg,bg)):
                        color=32+offset*2+side
                        curses.init_color(color,*(int(rgb[i:i+2],16)*1000//255 for i in (1,3,5)))
                        colors[side]=color
                curses.init_pair(index,*colors)
            else:
                curses.init_pair(index,curses.COLOR_BLACK,curses.COLOR_WHITE)
        for name, index in STYLES.items():
            palette[name] = curses.color_pair(index)
        palette["model_name"] |= curses.A_BOLD
        palette["title"] |= curses.A_BOLD
        palette["panel_header"] |= curses.A_BOLD
        palette["muted"] |= curses.A_DIM
    except curses.error:
        palette["selected"] = curses.A_REVERSE
        palette["header"] = curses.A_REVERSE
        palette["plain_header"] = curses.A_REVERSE
        palette["panel_header"] = curses.A_REVERSE
    return palette


def human_bytes(value):
    for suffix in ("B", "K", "M", "G", "T"):
        if abs(value) < 1024 or suffix == "T":
            return "%.1f%s" % (value, suffix)
        value /= 1024


def cpu_time(ticks):
    seconds = ticks / os.sysconf("SC_CLK_TCK")
    return "%d:%05.2f" % (seconds // 60, seconds % 60)


def process_line(row, width, advice="-"):
    cmd = "  " * row.get("depth", 0) + ("|- " if row.get("depth") else "") + ("* " if row.get("_tagged") else "") + (row.get("command_line", row["comm"]) if row.get("_show_command") else row["comm"])
    tid = row["tid"]
    user = safe(row.get("user", str(row.get("uid", "?"))))[:8]
    if width >= 110:
        return ("%7d %-8s %3s %3s %7s %7s %s %6.1f %5.1f %10s %-12s %s" %
                (tid, user, row.get("priority", "-"), row.get("nice", "-"),
                 human_bytes(row.get("vsize", 0)), human_bytes(row["rss_mb"] * 1048576),
                 row["state"], row.get("cpu", 0), row.get("memory_percent", 0),
                 cpu_time(row["ticks"]), advice[:12], cmd))
    return ("%6d %-8s %6s %s %5.1f %5.1f %8s %-12s %s" %
            (tid, user, human_bytes(row["rss_mb"] * 1048576), row["state"],
             row.get("cpu", 0), row.get("memory_percent", 0), cpu_time(row["ticks"]), advice[:12], cmd))


def draw_htop(screen, rows, engine, state, system, palette=None, coverage="proc snapshots; not syscall coverage"):
    palette = palette or dict.fromkeys(STYLES, 0)
    height, width = screen.getmaxyx()
    screen.erase()
    def put(y, x, text, style="normal", limit=None):
        if not (0 <= y < height and 0 <= x < width):
            return
        text = fit(text, min(width - x - 1, limit if limit is not None else width))
        try:
            screen.addnstr(y, x, text, len(text), palette[style])
        except curses.error:
            pass
    def bar(y, x, label, value, total=100, caption=None, limit=34, style="green"):
        right = caption or (" wait" if value is None else "%5.1f%%" % value)
        available = max(4, limit - 6 - len(right))
        ratio = max(0, min(1, value / total)) if value is not None and total else 0
        units = int(ratio * available)
        put(y, x, "%-4s[" % label)
        put(y, x + 5, "|" * units, style)
        put(y, x + 5 + units, "." * (available - units), "muted")
        put(y, x + 5 + available, "]" + right)

    if width < 60 or height < 16:
        put(0, 0, "MOP: resize terminal to at least 60x16; q exits", "title")
        screen.refresh()
        return
    stats, gran = engine.summary(), engine.granularity.summary()
    items = state.visible(rows, engine.recent, engine.latest_advice.values())
    cpus = system.get("cpu_percent", {})
    names = sorted((k for k in cpus if k != "cpu"), key=lambda k: int(k[3:]))
    shown = names[:8]
    put(0, 0, "H-MOP " + __version__ + " | SECURITY OBSERVER | %s | CPU 0-%d/%d (host)" %
        (stats["provider"], max(0, len(shown) - 1), len(names)), "title")
    half = width // 2
    for i in range(8):
        name = shown[i] if i < len(shown) else None
        if name:
            val = cpus[name]
            bar(1 + i // 2, (i % 2) * half, name[3:], val,
                limit=half - 2, style="red" if val is not None and val > 85 else "green")
    bar(5, 0, "Mem", system.get("memory_used", 0), system.get("memory_total", 0),
        caption=human_bytes(system.get("memory_used", 0)) + "/" + human_bytes(system.get("memory_total", 0)), limit=half - 2, style="blue")
    bar(5, half, "Swp", system.get("swap_used", 0), system.get("swap_total", 0),
        caption=human_bytes(system.get("swap_used", 0)) + "/" + human_bytes(system.get("swap_total", 0)), limit=half - 2, style="red")
    uptime = int(system.get("uptime", 0))
    put(6, 0, "Tasks: %d total | Running: %d | Load: %s | Up: %dd %02d:%02d" %
        (len({r["pid"] for r in rows}), sum(r["state"] == "R" for r in rows), system.get("load", "-"),
         uptime // 86400, uptime // 3600 % 24, uptime // 60 % 60))
    put(7, 0, banner(stats), severity(stats))
    put(8, 0, "%s %.0fms | p95 %.1fms | %s%s" %
        (gran["level"], gran["window_ms"], stats["inference_p95_ms"],
         coverage, " | SYNTHETIC DEMO" if system.get("demo") else ""), "muted")
    header = (" DECISION    PID/TID       N  INFER ms  QUEUE ms  OPERATION" if state.events else
              "    PID USER      PRI  NI    VIRT     RES S   CPU%  MEM%      TIME+ ADVICE       Command" if width >= 110 else
              "   PID USER        RES S  CPU%  MEM%    TIME+ ADVICE       Command")
    put(9, 0, " " * (width - 1), "header")
    put(9, 0, header, "header")
    page = height - 12
    if state.index < state.top:
        state.top = state.index
    if state.index >= state.top + page:
        state.top = state.index - page + 1
    state.top = min(max(0, state.top), max(0, len(items) - page))
    for visible, index in enumerate(range(state.top, min(len(items), state.top + page))):
        item = items[index]
        if state.events:
            event, verdict = item["event"], item["verdict"]
            text = "%-9s %6d/%-6d %4d %9.1f %9.1f  %s" % (
                (verdict["category"]), event["pid"], event["tid"], item.get("raw_event_count", 1),
                item["inference_ms"], item["queue_ms"], event["operation"])
            style = {"normal": "green", "high_risk": "red", "suspicious": "yellow"}.get(verdict["category"], "muted")
        else:
            advice = item.get("_advice", "-")
            text = process_line(item, width, advice)
            style = "red" if advice == "high_risk" else "yellow" if advice in ("unknown", "suspicious") else "normal"
        if index == state.index:
            put(10 + visible, 0, " " * (width - 1), "selected")
            style = "selected"
        put(10 + visible, 0, text, style)
    if not items:
        put(10, 1, "No matching rows", "muted")
    status = ("Search: " + state.query if state.editor == "search" else
              "Filter: " + state.filter if state.editor == "filter" else
              "%d/%d | sort:%s%s | filter:%s | Tab view  H threads  g level  [ ] period" %
              (state.index + 1 if items else 0, len(items), state.sort,
               " desc" if state.descending else " asc", state.filter or "-"))
    put(height - 2, 0, state.view_status() + " | " + status, "title")
    footer = [(1, "Help"), (2, "Setup"), (3, "Search"), (4, "Filter"), (5, "Tree"),
              (6, "Sort"), (7, "Nice-"), (8, "Nice+"), (9, "Signal"), (10, "Quit")]
    if width < 80:
        footer = [(1, "Help"), (3, "Find"), (4, "Filt"), (5, "Tree"), (6, "Sort"), (9, "Signal"), (10, "Quit")]
    x = 0
    for number, label in footer:
        key = "F" + str(number)
        put(height - 1, x, key, "key")
        x += len(key)
        put(height - 1, x, label + " ")
        x += len(label) + 1
    draw_overlay(put, state, items, engine, width, height)
    screen.refresh()


def draw_overlay(put, state, items, engine, width, height):
    gran = engine.granularity.summary()
    if state.overlay or state.control_kind:
        if state.control_kind:
            title = 'Confirm process action' if state.control_confirm else 'MOP ' + state.control_kind
            if state.control_kind in {'signal', 'nice'}:
                target = state.control_target
                lines = ['PID %s: %s' % (target.get('pid'), target.get('comm')),
                         ('Signal (1 HUP, 2 INT, 9 KILL, 15 TERM, 18 CONT, 19 STOP)' if state.control_kind == 'signal' else 'Nice value (-20..19; kernel permissions apply)'),
                         'Value: ' + state.control_value,
                         'Enter again to apply; Esc cancels.' if state.control_confirm else 'Edit value, Enter to review; Esc cancels.',
                         'Only this explicitly selected process is affected.']
            else:
                lines = [('User name or UID; empty means all users' if state.control_kind == 'user' else 'Sampling interval in seconds (0.1..10)'),
                         'Value: ' + state.control_value, 'Enter applies; Esc cancels.']
            if state.notice: lines.append(state.notice)
        elif state.overlay == 'cpus':
            title = 'Per-CPU utilization'
            lines = ['%s: %s' % (name, 'sampling' if value is None else '%.1f%%' % value)
                     for name,value in state.cpu_values.items() if name != 'cpu'] or ['Waiting for CPU samples']
        elif state.overlay == 'command':
            title='MOP command'
            lines=['> '+state.command_text,'Enter runs; Esc cancels.',
                   'models list | models probe NAME | models add MANIFEST',
                   'models shadow NAME | models active NAME | models disable NAME',
                   'models versions | models rollback REVISION',
                   'rules add ID "Plain-language review policy"',
                   'rules list | rules disable ID | rules remove ID']
        elif state.overlay == "help":
            title = "MOP help"
            lines = ["m: model slots; : model and policy commands", "Arrows / PgUp / PgDn / Home / End: select rows",
                     "F3 or /: search; n: next match; F4: filter",
                     "F5 or t: tree; F6: sort; P/M/T: CPU/memory/time",
                     "H: threads; Tab: processes / decisions; I: reverse sort",
                     "F7/F8: nice -/+ with confirmation; [ ]: inference window",
                     "Space: tag process; y: tagged only; U: clear tags",
                     "i: hide idle; =: clear display filters",
                     "z: freeze list (monitoring continues); +/-: faster/slower sampling",
                     "F4 filters: advice:high_risk cpu>5 mem>100 user:alice",
                     "F9: signal selected process; Enter: details; F10 / q: quit",
                     "k/r (top), K/R (all views): signal / renice, with confirmation",
                     "c: command line; u: user filter; d (top): refresh interval",
                     "1: CPU details (top/htop); Enter: process details",
                     "Security advice never automatically controls processes.",
                     "Arrows / PgUp / PgDn scroll panels; Esc or Enter closes."]
        elif state.overlay == "setup":
            title = "MOP setup"
            lines = ["Sampling interval: %.2fs (+/- in main view)" % state.interval,
                     "Runtime evidence: %s | periodic review: %.0fs" % ("on" if engine.evidence_collector else "off", engine.review_interval), "Level: " + gran["level"], "Target window: %.0f ms" % gran["window_ms"],
                     "Available: " + ", ".join(gran["available_levels"]),
                     "Max events/group: %d  Max groups: %d" % (gran["max_events"], gran["max_groups"]),
                     "g cycles level; [ ] changes window; Esc closes.",
                     "Changes apply in memory; use CLI/JSON for persistent config."]
            batching=engine.summary().get("batching")
            if batching and "batch_size_limit" in batching:
                lines[2:2]=[
                    "Native microbatch: %d decisions x %d batches" % (batching["batch_size_limit"],batching["max_batches"]),
                    "Coalescing wait: %.1f ms; pending: %d" % (batching["batch_wait_limit_ms"],batching["pending"]),
                    "Mode: classification"]
        elif state.overlay == "sort":
            title = "Sort by (arrows, Enter)"
            lines = [(" > " if i == state.sort_index else "   ") + label for i, label in enumerate(SORTS)]
        else:
            title = "Selected row details"
            if not items:
                lines = ["No row selected"]
            elif state.events:
                rec = items[state.index]
                lines = ["Category: " + (rec["verdict"]["category"]), "Reason: " + rec["verdict"]["reason"],
                         "Operation: " + rec["event"]["operation"],
                         "Unit represents %d raw events; group approval is not per-event clearance" % rec.get("raw_event_count", 1),
                         "Task: " + str(rec["event"].get("context", {}).get("task_id", "-")),
                         "Event: " + rec["event"]["id"],
                         "Evidence (untrusted observed data):",
                         *json.dumps(rec["event"].get("metadata", {}), indent=2, ensure_ascii=False).splitlines()]
            else:
                row = items[state.index]
                lines = ["Name: " + row["comm"], "PID / TID / PPID: %d / %d / %d" % (row["pid"], row["tid"], row["ppid"]),
                         "User: " + row.get("user", str(row["uid"])),
                         "CPU: %.1f%%  RES: %.1f MiB" % (row.get("cpu", 0), row["rss_mb"]),
                         "Arguments are redacted; environment credentials and memory contents are excluded.",
                         "This panel does not send signals or change permissions."]
                rec = next((rec for rec in reversed(engine.latest_advice.values())
                    if advice_for(row, [rec]) != "-"), None)
                if rec:
                    verdict = rec["verdict"]
                    lines[4:4] = ["Latest advice: " + (verdict["category"]),
                        "Observation age: %.1fs | inference %.1fms" % (max(0, time.time() - rec["event"]["timestamp"]), rec["inference_ms"]),
                        "Operation: " + rec["event"]["operation"],
                        "Scores (not calibrated): " + ", ".join("%s=%.3f" % (k, v) for k, v in verdict.get("probabilities", {}).items())]
                    evidence = rec["event"]["metadata"].get("runtime_evidence")
                    if evidence:
                        lines.insert(8, "Runtime evidence: %d FD entries, %d log tails; %d declared gaps" % (
                            len(evidence.get("system", {}).get("open_files", [])), len(evidence.get("logs", [])), len(evidence.get("gaps", []))))
                        lines.insert(9, "Network: %d | parents: %d | sufficiency: limited" % (len(evidence.get("system",{}).get("connections",[])), len(evidence.get("system",{}).get("ancestry",[]))))
                        lines.insert(10, "Evidence collection: %.1fms%s" % (rec.get("evidence_ms", 0),
                            " | truncated to budget" if evidence.get("truncated_to_budget") else ""))
                else:
                    lines.insert(4, "Latest advice: no matching retained result")
        if state.overlay=='details' and items:
            chosen=items[state.index] if state.events else next((r for r in reversed(engine.latest_advice.values()) if advice_for(items[state.index],[r])!='-'),None)
            if chosen:
                decision=chosen['verdict']
                extra=['Policy revision: '+decision.get('policy_revision',''),
                       'Policy rules supplied: '+', '.join(decision.get('policy_rules',[])),
                       'Action: observed']
                for trace in decision.get('guard_trace',[]):
                    extra+=['Model: '+trace['name']+' @ '+trace['version']+' ['+trace['state']+']',
                            '  '+trace['category']+' | %.1f ms'%trace['latency_ms']+' | confidence '+str(trace['confidence']),
                            '  '+trace['reason']]
                lines[0:0]=extra+['']
        box_w = min(width - 4, max(48, min(100, max(map(len, lines + [title])) + 4)))
        lines = [part for line in lines for part in (textwrap.wrap(safe(line), max(8, box_w - 4), replace_whitespace=False) or [""])]
        box_h = min(height - 2, len(lines) + 4)
        left, top = (width - box_w) // 2, (height - box_h) // 2
        for y in range(top, top + box_h):
            put(y, left, " " * box_w, "key")
        put(top, left, fit(" " + title + " ", box_w), "header")
        page = max(1, box_h - 4)
        state.overlay_max = max(0, len(lines) - page)
        state.overlay_offset = min(state.overlay_offset, state.overlay_max)
        put(top + box_h - 1, left + 1, " %d-%d/%d | Up/Down scroll | Esc close" % (state.overlay_offset + 1, min(len(lines), state.overlay_offset + page), len(lines)), "muted", box_w - 2)
        for i, line in enumerate(lines[state.overlay_offset:state.overlay_offset + page]):
            put(top + 2 + i, left + 2, line, "key", box_w - 4)


def draw(screen, rows, engine, state, system, palette=None, coverage="proc snapshots; not syscall coverage"):
    if state.overlay=='models':
        from .model_panel import draw as draw_models
        return draw_models(screen,engine,state,palette or dict.fromkeys(STYLES,0))
    from .frontends import draw_top, draw_btop
    if engine.stats.get('ambient_enabled'):
        if engine.stats.get('ambient_source_unavailable'):
            coverage += '; content unavailable'
        else:
            coverage += '; content partial'
        coverage += '; gaps %d' % engine.stats.get('ambient_capture_gaps', 0)
    if engine.stats.get('network_enabled'):
        coverage += '; proxy '+('unavailable' if engine.stats.get('network_source_unavailable') else 'routed traffic')
    renderer = {"top": draw_top, "htop": draw_htop, "btop": draw_btop}[state.profile]
    return renderer(screen, rows, engine, state, system,
                    palette or dict.fromkeys(STYLES, 0), coverage)


async def _run(screen, engine, duration, interval, all_users=False, initial_threads=False, task=None, ui="htop", user_filter='', pid_filter=(), iterations=None):
    palette = initialize(screen)
    state = ViewState(events=task is not None, threads=initial_threads, profile=ui)
    rows, system, previous_system, last_rows = [], {}, {}, {}
    state.interval = interval
    state.user_filter = user_filter or ''; state.pid_filter = set(pid_filter)
    samples = 0
    reviewed = {}
    end = time.monotonic() + duration if duration is not None else float("inf")
    next_sample, last_time = 0, time.monotonic()
    ticks = os.sysconf("SC_CLK_TCK")
    model_job=None
    buffered_key=None
    async def model_command(words):
        import sys
        process=await asyncio.create_subprocess_exec(*python_command(*words),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        try:
            output,_=await asyncio.wait_for(process.communicate(),15)
            return process.returncode,output.decode('utf-8','replace').strip()[:300]
        except (asyncio.TimeoutError,asyncio.CancelledError):
            if process.returncode is None:process.kill()
            await process.wait()
            raise
    while time.monotonic() < end:
        if getattr(engine,"remote",False):await engine.refresh(models_only=state.overlay=="models")
        if task is not None and task.done():
            engine.granularity.flush("source_finished")
            if not engine.queue.qsize() and not engine.stats["in_flight"]:
                return await task
        items = state.visible(rows, engine.recent, engine.latest_advice.values())
        height = screen.getmaxyx()[0] if hasattr(screen, "getmaxyx") else 24
        from .frontends import page_rows
        key = screen.getch() if buffered_key is None else buffered_key
        buffered_key=None
        navigation={curses.KEY_UP,curses.KEY_DOWN,curses.KEY_PPAGE,curses.KEY_NPAGE,curses.KEY_HOME,curses.KEY_END}
        if key in navigation:
            for _ in range(15):
                following=screen.getch()
                if following not in navigation:
                    if following!=-1:buffered_key=following
                    break
                state.key(key,engine,items,page_rows(ui,height));key=following
        h, w = screen.getmaxyx() if hasattr(screen, "getmaxyx") else (24, 120)
        if (h < (24 if ui == 'btop' and state.overlay != 'models' else 16) or w < (80 if ui == 'btop' and state.overlay != 'models' else 60)) and key not in (ord('q'),27,curses.KEY_F10):
            key = -1
        previous_command_mode = state.show_command
        if state.key(key, engine, items, page_rows(ui, height)):
            if model_job and not model_job.done():
                model_job.cancel();await asyncio.gather(model_job,return_exceptions=True)
            return 130 if task is not None else 0
        if state.model_action and model_job is None:
            model_job=asyncio.create_task(model_command(state.model_action));state.model_action=[]
        if model_job and model_job.done():
            try:code,message=model_job.result()
            except Exception as error:code,message=2,type(error).__name__
            state.model_results[state.model_busy]={'ok':code==0}
            state.model_notice=message
            state.model_busy='';model_job=None
            if hasattr(engine.provider,'reload'):engine.provider.reload(force=True)
            if getattr(engine,'remote',False):engine.next_refresh=0
        if state.pending_command:
            import shlex, sys
            command=state.pending_command;state.pending_command=''
            try:
                words=shlex.split(command)
                if not words or words[0] not in {'models','rules'}:raise ValueError('Use models or rules commands')
                process=await asyncio.create_subprocess_exec(*python_command(*words),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
                try:output,_=await asyncio.wait_for(process.communicate(),15)
                except asyncio.TimeoutError:
                    process.kill();await process.wait();raise ValueError('Command timed out')
                state.notice=output.decode('utf-8','replace').strip()[:300]
                if hasattr(engine.provider,'reload'):engine.provider.reload(force=True)
            except ValueError as error:state.notice=str(error)
        if state.show_command != previous_command_mode: next_sample = 0
        if state.pending_control is not None:
            from .process_control import apply_action
            target, action, value = state.pending_control
            state.pending_control = None
            try:
                state.notice = await asyncio.to_thread(apply_action, target, action, value)
                engine.submit(Event('user_process_control','ui',metadata={
                    'target_pid':target['pid'],'start_ticks':target['start_ticks'],
                    'action':action,'value':value,'success':True}))
            except (OSError, ValueError) as error:
                state.notice = type(error).__name__ + ': ' + str(error)
            next_sample = 0
        now = time.monotonic()
        if now >= next_sample and not (getattr(engine,"remote",False) and state.overlay=="models"):
            rows, denied = await asyncio.to_thread(snapshot, all_users=True, threads=state.threads)
            if state.show_command:
                from .process_control import command_line
                candidates = state.visible(rows, engine.recent, engine.latest_advice.values())
                page = max(1,page_rows(ui,height))
                first = max(0,min(state.top,state.index))
                if state.index >= first+page: first=state.index-page+1
                visible_ids = {identity(row) for row in candidates[first:first+page]}
                def commands():
                    for row in rows:
                        if identity(row) in visible_ids: row['command_line'] = command_line(row)
                await asyncio.to_thread(commands)
            if task is None: engine.retain_visible_identities(rows)
            system = await asyncio.to_thread(read_system)
            system["cpu_percent"] = cpu_percent(system, previous_system)
            state.cpu_values = system['cpu_percent']
            previous_system = system
            current_stats = engine.summary()
            from .security_view import status
            state.history["cpu"].append(system["cpu_percent"].get("cpu"))
            state.history["latency"].append(current_stats["inference_p95_ms"])
            state.history["waiting"].append(status(current_stats)["waiting"])
            now = time.monotonic()
            current = {}
            for row in rows:
                ident = identity(row)
                old = last_rows.get(ident)
                row["cpu"] = (max(0, 100 * (row["ticks"] - old["ticks"]) / ticks / max(now - last_time, .001))
                              if old else 0)
                row["memory_percent"] = (row["rss_mb"] * 1048576 / system["memory_total"] * 100
                                         if system.get("memory_total") else 0)
                current[ident] = row
                due = engine.review_interval > 0 and now - reviewed.get(ident, -float("inf")) >= engine.review_interval
                from .pipeline_identity import is_monitor
                if task is None and not is_monitor(row['pid']) and (not pid_filter or row['pid'] in pid_filter) and (all_users or row['uid'] == os.getuid()) and (ident not in reviewed or due) and row["pid"] != os.getpid():
                    accepted = engine.submit(Event("process_review" if ident in reviewed else "task_discovered", "proc-poll", row["pid"], row["tid"], row["comm"],
                                        metadata={"not_a_syscall": True, "start_ticks": row["start_ticks"]}))
                    if accepted: reviewed[ident] = now
            reviewed = {key: value for key, value in reviewed.items() if key in current}
            engine.stats["proc_inaccessible"] = denied
            last_rows, last_time = current, now
            next_sample = now + state.interval
            samples += 1
        draw(screen, rows, engine, state, system, palette,
             "traced command only; no blocking" if task is not None else ('all-user display; all-user review' if all_users else 'all-user display; own-user review') + ('; kernel unavailable' if engine.stats.get('kernel_source_unavailable') else ''))
        if iterations is not None and samples >= iterations: return 0
        await asyncio.sleep(.02 if state.overlay=="models" else .05)
    if model_job and not model_job.done():
        model_job.cancel();await asyncio.gather(model_job,return_exceptions=True)
    return await task if task is not None else 0


async def monitor(screen, engine, duration, interval, all_users, initial_threads=False, ui="htop", **kwargs):
    return await _run(screen, engine, duration, interval, all_users, initial_threads, ui=ui, **kwargs)


async def event_monitor(screen, engine, task, interval=.2, ui="htop"):
    try:
        return await _run(screen, engine, float("inf"), interval, task=task, ui=ui)
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
