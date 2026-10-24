"""Render all three real UI profiles using live snapshots or explicit demo fixtures."""
import html
import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mop.core import Engine, Event
from mop.classification import ClassificationProvider
from mop.proc import snapshot
from mop.meters import read_system, cpu_percent
from mop.ui import draw, STYLES
from mop.ui_state import ViewState, identity


class Buffer:
    def __init__(self, height=34, width=120):
        self.height, self.width = height, width
        self.erase()
    def getmaxyx(self): return self.height, self.width
    def erase(self):
        self.grid = [[[" ",0] for _ in range(self.width)] for _ in range(self.height)]
    def refresh(self): pass
    def addnstr(self, y, x, text, count, style=0):
        for i,c in enumerate(text[:count]):
            if x+i < self.width:
                self.grid[y][x+i] = [c, style]


def demo():
    names = ["workspace-agent","mcp-bridge","curl","python-worker","vllm-jev","mop-collector"]
    rows = [dict(pid=2100+i,tid=2100+i,ppid=2100 if i else 1,start_ticks=100+i,
                 comm=name,user="demo",uid=1000,state="R" if i in (0,4) else "S",
                 priority=20,nice=0,cpu=[24.5,3.2,.3,12.1,87.4,1.2][i],
                 rss_mb=[640,128,12,256,4096,48][i],memory_percent=[2,.4,.1,.8,12.5,.15][i],
                 ticks=1000+i*250,vsize=(1024+i*128)*1048576)
            for i,name in enumerate(names)]
    system = dict(demo=True,cpu_percent={"cpu":42,**{"cpu"+str(i):v for i,v in enumerate([34,62,28,47,85,31,22,27])}},
                  memory_total=32*1024**3,memory_used=12*1024**3,swap_total=4*1024**3,
                  swap_used=0,load="2.84 2.10 1.92",uptime=97000)
    engine=Engine(ClassificationProvider("http://127.0.0.1:18936"),level="thread")
    outcomes=["suspicious","suspicious","high_risk","unknown","normal","suspicious"]
    operations=["open_sensitive","tool_call","connect_external","read_document","model_response","process_exec"]
    for i,row in enumerate(rows):
        event=Event(operations[i],"synthetic-preview",pid=row["pid"],tid=row["tid"],comm=row["comm"],
                    metadata={"synthetic":True,"start_ticks":row["start_ticks"]})
        latency=[48,51,67,50,37,42][i]
        engine.recent.append({"event":event.payload(),"verdict":{"category":outcomes[i],"reason":"Synthetic UI fixture; not a real security finding"},
                              "inference_ms":latency,"queue_ms":i*3,"raw_event_count":1,
                              "decision_scope":"event","enforced":False})
        engine.inference_ms.append(latency)
        engine.latest_advice[identity(row)]=engine.recent[-1]
        if outcomes[i]!="unknown": engine.category_counts[outcomes[i]]+=1
    engine.stats.update(raw_events_received=18,raw_events_in_completed_units=6,raw_events_enqueued=6,
                        completed=6,accepted=6,unknown=1,
                        raw_dropped_queue_full=4,dropped_queue_full=4,events_buffered=8)
    return rows,system,engine


def live():
    previous_rows,_=snapshot()
    previous_system=read_system()
    start=time.monotonic()
    time.sleep(.25)
    rows,_=snapshot()
    system=read_system()
    elapsed=time.monotonic()-start
    previous={identity(r):r for r in previous_rows}
    ticks=os.sysconf("SC_CLK_TCK")
    for row in rows:
        old=previous.get(identity(row))
        row["cpu"]=max(0,100*(row["ticks"]-old["ticks"])/ticks/elapsed) if old else 0
        row["memory_percent"]=row["rss_mb"]*1048576/system["memory_total"]*100 if system["memory_total"] else 0
    system["cpu_percent"]=cpu_percent(system,previous_system)
    return rows,system,Engine(ClassificationProvider("http://127.0.0.1:18936"))


p=argparse.ArgumentParser()
p.add_argument("--models",action="store_true",help="render the live daemon model panel")
p.add_argument("--demo",action="store_true",help="explicitly synthetic advice/history for visual review")
p.add_argument("--ui",choices=["all","top","htop","btop"],default="all")
args=p.parse_args()
if args.models and args.demo:p.error('Use either live model slots or demo data')
rows,system,engine=demo() if args.demo else live()
if args.models:
    import asyncio
    from mop.daemon import RemoteEngine,RemoteGranularity
    engine=RemoteEngine();engine.granularity=RemoteGranularity(engine)
    asyncio.run(engine.refresh())
out=Path(__file__).resolve().parents[1]/"artifacts"
out.mkdir(exist_ok=True)
for profile in (("top","htop","btop") if args.ui=="all" else (args.ui,)):
    state=ViewState(profile=profile)
    if args.models:state.overlay="models"
    if args.demo:
        state.history["cpu"].extend(30+20*math.sin(i/4)+i/5 for i in range(50))
        state.history["latency"].extend(45+12*math.sin(i/3) for i in range(50))
        state.history["waiting"].extend(max(0,8+6*math.sin(i/5)) for i in range(50))
    screen=Buffer(height=40 if args.models else {"top":24,"htop":28,"btop":34}[profile], width=140 if args.models else 120)
    draw(screen,rows,engine,state,system,STYLES,
         "SYNTHETIC DEMO; not security evidence" if args.demo else "proc snapshots; scoped visibility")
    path=out/("mop-"+profile+"-buffer.json")
    path.write_text(json.dumps({"grid":screen.grid,"width":screen.width,"height":screen.height,
                               "profile":profile,"demo":args.demo,
                               "caption":"SYNTHETIC DEMO / actual renderer / not security evidence" if args.demo else
                                         "Actual renderer / read-only host snapshot / no inference performed"}))
    print(path)

    colors={0:("#dce5ed",None),1:("#66d9ef",None),2:("#81c784",None),3:("#ffd166",None),4:("#ff7070",None),5:("#80aaff",None),6:("#101820","#81c784"),7:("#101820","#66d9ef"),8:("#f0f4f8","#244b75"),9:("#9aabbc",None),10:("#101820","#dce5ed"),11:("#66d9ef",None)}
    from mop.model_panel import THEME
    colors.update({12+i:(fg,bg) for i,(_,fg,bg,_,_) in enumerate(THEME)})
    width,height=screen.width*8+24,screen.height*18+24
    svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="MOP {profile} renderer preview">',
         f'<rect width="{width}" height="{height}" fill="#101820"/>','<g font-family="DejaVu Sans Mono,monospace" font-size="13" xml:space="preserve">']
    for y,row in enumerate(screen.grid):
        x=0
        while x<len(row):
            style=row[x][1];end=x+1
            while end<len(row) and row[end][1]==style:end+=1
            text="".join(cell[0] for cell in row[x:end]);fg,bg=colors[style]
            if bg:svg.append(f'<rect x="{12+x*8}" y="{12+y*18}" width="{(end-x)*8}" height="18" fill="{bg}"/>')
            if text.strip():svg.append(f'<text x="{12+x*8}" y="{25+y*18}" fill="{fg}" textLength="{len(text)*8}" lengthAdjust="spacingAndGlyphs">{html.escape(text)}</text>')
            x=end
    svg+=['</g>','</svg>']
    (out/('mop-'+profile+'.svg')).write_text("\n".join(svg)+"\n")
