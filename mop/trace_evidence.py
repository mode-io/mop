"""Decoded strace observations from the private tracer channel, not task stderr."""
import ast
import json
import re
from collections import OrderedDict
from .evidence import redact
from .system_facts import SECRET_FLAG

RESUMED=re.compile(r'^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(\d+\.\d+)\s+<\.\.\.\s+(\w+) resumed>(.*)$')
PREFIX=re.compile(r'^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(\d+\.\d+)\s+(\w+)\(')


def safe_arguments(text):
    matches=list(re.finditer(r'"(?:\\.|[^"\\])*"',text))
    replacements=[];hide_next=False
    for match in matches:
        try:value=ast.literal_eval(match.group())
        except (ValueError,SyntaxError):continue
        if hide_next:
            replacements.append((match.start(),match.end(),'"[REDACTED]"'));hide_next=False
        elif value.startswith('-') and SECRET_FLAG.fullmatch(value.split('=',1)[0].lstrip('-')):
            if '=' in value:replacements.append((match.start(),match.end(),json.dumps(value.split('=',1)[0]+'=[REDACTED]')))
            else:hide_next=True
    for start,end,replacement in reversed(replacements):text=text[:start]+replacement+text[end:]
    return redact(text)


class TraceDecoder:
    def __init__(self,parse,details=True):
        self.parse,self.details=parse,details
        self.pending=OrderedDict()
        self.unmatched_resumes=0;self.evicted=0
    def feed(self,line):
        resumed=RESUMED.match(line)
        if resumed:
            key=(int(resumed.group(1) or resumed.group(2) or 0),resumed.group(4))
            previous=self.pending.pop(key,None)
            if previous is None:self.unmatched_resumes+=1;return None
            event=self.parse(previous+resumed.group(5),self.details)
            if event:event.metadata['completion_timestamp']=float(resumed.group(3))
            return event
        match=PREFIX.match(line)
        if match and '<unfinished ...>' in line:
            key=(int(match.group(1) or match.group(2) or 0),match.group(4))
            self.pending[key]=line.split('<unfinished ...>',1)[0]
            if len(self.pending)>256:self.pending.popitem(last=False);self.evicted+=1
            return None
        return self.parse(line,self.details)
    def finish(self):
        events=[]
        for text in self.pending.values():
            event=self.parse(text+'<unfinished ...>',self.details)
            if event:
                event.metadata['completion']='not observed'
                events.append(event)
        self.pending.clear();return events


def syscall_boundary(line,start):
    """Find the outer call close, ignoring quoted strings and FD annotations."""
    depth=1;quoted=False;escaped=False;annotation=False
    for index in range(start,len(line)):
        char=line[index]
        if quoted:
            if escaped:escaped=False
            elif char=="\\":escaped=True
            elif char=='"':quoted=False
            continue
        if annotation:
            if char=='>':annotation=False
            continue
        if char=='"':quoted=True
        elif char=='<':annotation=True
        elif char=='(':depth+=1
        elif char==')':
            depth-=1
            if depth==0:return index
    return None
