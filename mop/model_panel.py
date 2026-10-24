"""Film-inspired model cards, backed by live slot state."""
import curses
import time

CATALOG = (
    ('jev-core', 'JV', 'core safety judge', 'model_core'),
    ('guard-privacy', 'PV', 'personal data / secrets', 'model_privacy'),
    ('guard-permission', 'PM', 'who may do what', 'model_permission'),
    ('guard-content', 'CT', 'scams / harmful replies', 'model_content'),
    ('guard-compliance', 'CP', 'GDPR / HIPAA / EU AI Act', 'model_compliance'),
)
# Pair names, foreground/background RGB, and 256-color fallbacks.
THEME = (
    ('model_bg', '#161623', '#8c8aa4', 234, 103),
    ('model_border', '#686b20', '#8c8aa4', 58, 103),
    ('model_card', '#161623', '#aaa9bc', 234, 146),
    ('model_line', '#757722', '#aaa9bc', 100, 146),
    ('model_muted', '#505064', '#aaa9bc', 240, 146),
    ('model_action', '#247781', '#aaa9bc', 30, 146),
    ('model_loaded', '#23754e', '#aaa9bc', 29, 146),
    ('model_core', '#ffffff', '#c57651', 231, 173),
    ('model_privacy', '#ffffff', '#78609e', 231, 97),
    ('model_permission', '#ffffff', '#427c9e', 231, 67),
    ('model_content', '#ffffff', '#ac653d', 231, 130),
    ('model_compliance', '#ffffff', '#968126', 231, 136),
    ('model_empty', '#eeeef2', '#9493a6', 255, 103),
    ('model_name', '#161623', '#aaa9bc', 234, 146),
    ('model_focus', '#205c6a', '#aaa9bc', 24, 146),
)

def cards(info):
    models = info.get('models', [])
    core = next((m for m in models if m.get('role') == 'core'), None)
    indexed = {m['name']: m for m in models if m is not core}
    result = []
    for name, badge, description, color in CATALOG:
        slot = core if name == 'jev-core' else indexed.pop(name, None)
        result.append(dict(name=name, badge=badge, description=description, color=color, slot=slot))
    for name, slot in indexed.items():
        result.append(dict(name=name, badge='MD', description='custom model slot', color='model_permission', slot=slot))
    return result


def loaded(slot, outcomes):
    if not slot or slot.get('state') == 'disabled': return False
    outcome = outcomes.get(slot['name'])
    if outcome is not None: return outcome['ok']
    return slot.get('calls', 0) > slot.get('unknown', 0) or slot.get('role') == 'specialist'


def command_for(card, key):
    slot = card['slot']
    if not slot:
        return ['models', 'install', card['name']] if key in (10,13,ord('i')) else None
    if key == ord('s') and slot.get('role') != 'core':
        return ['models', 'active' if slot['state'] == 'shadow' else 'shadow', slot['name']]
    if key == ord('d') and slot.get('role') != 'core':
        return ['models', 'active' if slot['state'] == 'disabled' else 'disable', slot['name']]
    if key in (ord('s'), ord('d')): return None
    return ['models', 'active' if slot['state'] == 'disabled' else 'probe', slot['name']]


def handle_key(state, key, engine):
    if key in (27, ord('q'), ord('m')):
        state.overlay = ''; return
    if key == ord(':'):
        state.overlay = 'command'; state.command_text = ''; return
    provider=getattr(engine,'provider',None)
    info = provider.model_status() if hasattr(provider, 'model_status') else {}
    rows = cards(info)
    if key==curses.KEY_MOUSE:
        try:_,x,y,_,buttons=curses.getmouse()
        except curses.error:return
        if buttons & curses.BUTTON4_PRESSED:key=curses.KEY_UP
        elif buttons & getattr(curses,'BUTTON5_PRESSED',0):key=curses.KEY_DOWN
        elif buttons & curses.BUTTON1_CLICKED:
            for index,x0,y0,x1,y1,action_x in state.model_hitboxes:
                if x0<=x<=x1 and y0<=y<=y1:
                    state.model_index=index
                    key=10 if x>=action_x else -1
                    break
    if key in (curses.KEY_HOME,):state.model_index=0
    elif key in (curses.KEY_END,):state.model_index=len(rows)-1
    elif key in (9,):state.model_index=(state.model_index+1)%len(rows)
    elif key==curses.KEY_BTAB:state.model_index=(state.model_index-1)%len(rows)
    elif key==curses.KEY_NPAGE:state.model_index=min(len(rows)-1,state.model_index+3)
    elif key==curses.KEY_PPAGE:state.model_index=max(0,state.model_index-3)
    elif key in (curses.KEY_UP, ord('k')): state.model_index = max(0, state.model_index - 1)
    elif key in (curses.KEY_DOWN, ord('j')): state.model_index = min(len(rows)-1, state.model_index + 1)
    elif key == ord('e'):
        state.model_notice = 'Enforce a command: mop gate --mode enforce -- COMMAND'
    elif key in (10, 13, ord('i'), ord('s'), ord('d')):
        if state.model_busy: return
        command = command_for(rows[min(state.model_index, len(rows)-1)], key)
        if command:
            state.model_action = command
            state.model_busy = command[-1]
            state.model_started = time.monotonic()
            state.model_notice = ''


def draw(screen, engine, state, palette):
    from .ui import fit
    height, width = screen.getmaxyx()
    screen.erase()
    state.model_hitboxes=[]
    def put(y, x, text, style='model_bg', limit=None):
        if 0 <= y < height and 0 <= x < width:
            try: screen.addnstr(y, x, fit(text, min(width-x-1, limit or width)), width-x-1, palette.get(style, 0))
            except curses.error: pass
    for y in range(height): put(y, 0, ' ' * width)
    if width < 60 or height < 16:
        put(1, 2, 'Models / resize to at least 60 x 16')
        put(3, 2, 'Esc returns to processes'); screen.refresh(); return
    info = engine.provider.model_status() if hasattr(engine.provider, 'model_status') else {}
    rows = cards(info)
    state.model_index = min(state.model_index, len(rows)-1)
    margin = max(2, min(10, width//14)); left=margin; right=width-margin-1
    top=2 if height>=28 else 1; bottom=height-3
    def box(y, x, w, h, style, selected=False):
        put(y,x,('╔'+'═'*(w-2)+'╗') if selected else ('╭'+'─'*(w-2)+'╮'),style)
        put(y+h-1,x,('╚'+'═'*(w-2)+'╝') if selected else ('╰'+'─'*(w-2)+'╯'),style)
        for line in range(y+1,y+h-1):
            put(line,x,'║' if selected else '│',style);put(line,x+w-1,'║' if selected else '│',style)
    box(top,left,right-left+1,bottom-top+1,'model_border')
    put(top,left+2,' GUARD / model slot ','model_border')
    count=sum(loaded(r['slot'],state.model_results) for r in rows)
    gran=engine.granularity.summary()
    core=next((r['slot'] for r in rows if r['slot'] and r['slot']['role']=='core'),None)
    latency=core.get('p95_ms') if core else None
    summary='models loaded %d/%d    Window %.0fms    review p95 %s' % (count,len(rows),gran['window_ms'], '--' if latency is None else '%.0fms'%latency)
    put(top+2,left+3,summary,'model_border',right-left-5)
    card_height=5 if height>=39 else 4 if height>=32 else 3
    start=top+5 if height>=28 else top+4
    available=max(1,(bottom-start-4)//card_height)
    state.model_top=max(0,min(state.model_top,max(0,len(rows)-available)))
    if state.model_index<state.model_top:state.model_top=state.model_index
    elif state.model_index>=state.model_top+available:state.model_top=state.model_index-available+1
    first=state.model_top
    card_x=left+3;card_w=right-left-5
    for index,card in enumerate(rows[first:first+available],first):
        y=start+(index-first)*card_height; slot=card['slot']
        good=loaded(slot,state.model_results)
        body_height=4 if card_height>=4 else 3
        for line in range(y,y+body_height):put(line,card_x,' '*card_w,'model_card')
        box(y,card_x,card_w,body_height,'model_focus' if index==state.model_index else 'model_line',index==state.model_index)
        title_y=y+1 if body_height==4 else y
        description_y=y+2 if body_height==4 else y+1
        put(y+1,card_x+1,'▶' if index==state.model_index else ' ','model_action')
        put(y+1,card_x+3,' '+card['badge']+' ',card['color'] if good else 'model_empty')
        put(title_y,card_x+9,' '+card['name']+' ','model_name',card_w-12)
        put(description_y,card_x+10,card['description'],'model_muted',max(10,card_w//2-10))
        status_x=card_x+max(26,int(card_w*.56))
        state.model_hitboxes.append((index,card_x,y,card_x+card_w-1,y+body_height-1,status_x))
        busy=state.model_busy in {card['name'],slot['name'] if slot else ''} and bool(state.model_busy)
        if busy:
            tick=int((time.monotonic()-state.model_started)*6)%4
            put(y+1,status_x,'checking '+'.'*(tick+1),'model_action',card_x+card_w-status_x-2)
        elif good:
            put(y+1,status_x,'✓ loaded','model_loaded')
            if card_w>=90:
                mode='shadow' if slot['state']=='shadow' else 'advice'
                value=slot.get('p95_ms')
                put(y+1,status_x+12,mode+(' / %.0fms'%value if value is not None else ''),'model_card',card_x+card_w-status_x-14)
        else:
            label='[ install ]' if slot is None else '[ enable ]' if slot['state']=='disabled' else '[ check ]'
            put(y+1,status_x,label,'model_action',card_x+card_w-status_x-2)
    selected=rows[state.model_index]; slot=selected['slot']
    footer=bottom-3
    put(footer,left+3,'mode   [ advise ]   enforce (gate)','model_border',right-left-5)
    detail=state.model_notice
    if not detail:
        detail=('OpenJev placeholder' if slot and 'placeholder' in slot.get('version','') else slot.get('model','') if slot else 'Install connects this slot to the core model as a shadow placeholder.')
    if slot and not state.model_notice:detail+=' / calls %d / unknown %d'%(slot.get('calls',0),slot.get('unknown',0))
    put(footer+1,left+3,detail,'model_bg',right-left-5)
    put(height-2,margin,'↑↓/Tab/wheel select   Enter install/check   s shadow   d disable   Esc back','model_bg')
    if info.get('reload_error'):put(height-1,margin,'Configuration reload failed: '+info['reload_error'],'model_border')
    screen.refresh()
