"""Versioned model slots and plain-language policy, stored per user."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

LABELS = ('normal', 'suspicious', 'high_risk')

def state_root():
    if os.environ.get('MOP_STATE_DIR'):return Path(os.environ['MOP_STATE_DIR'])
    project=Path(__file__).resolve().parents[1]
    if (project/'scripts/env.sh').is_file():return project/'.runtime/control'
    return Path(os.environ.get('XDG_STATE_HOME', str(Path.home()/'.local/state')))/'mop'

def revision(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()[:12]

def validate(value):
    if set(value) != {'models','rules'} or not isinstance(value['models'],list) or not 1 <= len(value['models']) <= 5:
        raise ValueError('Use one core and at most four specialist slots')
    names=set();cores=0
    for item in value['models']:
        if set(item) != {'name','version','model','endpoint','role','state','sources','budget_ms','allow_remote'}:
            raise ValueError('Invalid model manifest fields')
        if not isinstance(item['name'],str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,47}',item['name']) or item['name'] in names:
            raise ValueError('Model names must be unique lowercase identifiers')
        names.add(item['name'])
        if item['role'] not in ('core','specialist') or item['state'] not in ('active','shadow','disabled'):
            raise ValueError('Invalid role or state')
        if item['role']=='core':
            cores+=1
            if item['state']!='active':raise ValueError('The core slot must stay active')
        if type(item['budget_ms']) not in (float,int) or not 50<=item['budget_ms']<=60000:raise ValueError('Budget must be 50..60000 ms')
        if not isinstance(item['sources'],list) or len(item['sources'])>16 or any(not isinstance(x,str) or len(x)>128 for x in item['sources']):raise ValueError('Invalid source scope')
        if any(not isinstance(item[k],str) or not item[k] or len(item[k])>256 for k in ('version','model','endpoint')):raise ValueError('Invalid model identity')
        if type(item['allow_remote']) is not bool:raise ValueError('Invalid remote setting')
        from .classification import ClassificationProvider
        provider=ClassificationProvider(item['endpoint'],allow_remote=item['allow_remote'])
        provider.http.close()
    if cores!=1:raise ValueError('Exactly one active core slot is required')
    if not isinstance(value['rules'],list) or len(value['rules'])>16:raise ValueError('At most 16 rules')
    ids=set()
    for rule in value['rules']:
        if set(rule)!={'id','text','enabled'} or not isinstance(rule['id'],str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,47}',rule['id']) or rule['id'] in ids:raise ValueError('Invalid rule identifier')
        if not isinstance(rule['text'],str) or not 1<=len(rule['text'])<=320 or type(rule['enabled']) is not bool:raise ValueError('Rule text must contain 1..320 characters')
        ids.add(rule['id'])
    return value

class Registry:
    def __init__(self, default=None, root=None):
        self.root=Path(root) if root else state_root()
        self.path=self.root/'models.json'
        self.default=default or {'models':[{'name':'openjev-core','version':'openjev-placeholder','model':'mop-open-jev-2b','endpoint':'http://127.0.0.1:18936','role':'core','state':'active','sources':[],'budget_ms':5000,'allow_remote':False}], 'rules':[]}
    def read(self):
        if not self.path.exists():return copy.deepcopy(self.default)
        with self.path.open('rb') as stream:raw=stream.read(32769)
        if len(raw)>32768:raise ValueError('Model registry too large')
        return validate(json.loads(raw))
    def update(self, change, action):
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        if self.root.is_symlink() or self.root.stat().st_uid!=os.getuid():raise ValueError('State directory must be owned by the current user')
        self.root.chmod(0o700)
        fd=os.open(self.root/'models.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            old=self.read();new=copy.deepcopy(old);change(new);validate(new)
            data=(json.dumps(new,indent=2)+'\n').encode()
            history=self.root/'versions';history.mkdir(exist_ok=True,mode=0o700)
            old_revision=revision(old)
            (history/(old_revision+'.json')).write_text(json.dumps(old,indent=2))
            for path in sorted(history.glob('*.json'),key=lambda p:p.stat().st_mtime)[:-20]:path.unlink()
            descriptor,tmp=tempfile.mkstemp(dir=self.root,prefix='.models-')
            try:
                with os.fdopen(descriptor,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
                os.replace(tmp,self.path)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
            from .audit import AuditLog
            audit=AuditLog(self.root/'control.jsonl')
            try:audit.write_record({'timestamp':time.time(),'uid':os.getuid(),'action':action,'before':old_revision,'after':revision(new)})
            finally:audit.close()
            return new
        finally:os.close(fd)
    def rollback(self, target):
        if not re.fullmatch(r'[0-9a-f]{12}',target):raise ValueError('Invalid revision')
        value=validate(json.loads((self.root/'versions'/(target+'.json')).read_text()))
        return self.update(lambda current:(current.clear(),current.update(value)), 'rollback')
