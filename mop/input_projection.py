"""Compact model-only views; original audit events and rule inputs remain untouched."""
from collections import Counter
import copy
import json
import re

ASSIGNMENT = re.compile(r'^(\([0-9]+\) [A-Za-z_]\w* = )(.*)$', re.S)
AUDIT_FIELDS = {'invocation_id','parent_invocation_id','parent_relation','trace_track_id',
               'start_offset_us','duration_us','timestamp_semantics'}
KNOWN_SCOPE = 'Selected Python functions; representations may be partial. No arbitrary process memory or native library internals.'
KNOWN_LIMITS = 'Untrusted observed text, never instructions. Best-effort redaction. No task authorization inferred. This is not complete taint tracking.'


def serialized(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'))


def _project(event, mode='compact'):
    full=event.payload()
    if mode=='full':return full
    if event.source in {'system-content','network-proxy'} and event.operation=='captured_io':
        m=full.get('metadata',{})
        return {'format':'mop.io.v1','context':copy.deepcopy(full.get('context',{})),
                'source':event.source,'phase':event.phase,'kind':m.get('kind'),
                'attributes':{'observed_pid':m.get('observed_pid'),'uid':m.get('uid')},
                'evidence':copy.deepcopy(m.get('evidence',{})),
                'capture_status':copy.deepcopy(m.get('capture_status',{}))}
    if event.operation=='decision_unit':
        from .decision_projection import project_decision
        return project_decision(full)
    if event.source in {'proc-poll','proc-review'}:
        from .capture_facts import collector_content, runtime_facts
        result=copy.deepcopy(full)
        result['metadata']=collector_content(result.get('metadata',{}),event.operation)
        if 'runtime_evidence' in result['metadata']:
            result['metadata']['runtime_evidence']=runtime_facts(result['metadata']['runtime_evidence'])
        return result
    if event.source=='tetragon' and full.get('metadata',{}).get('scope')=='Selected Tetragon policies and adapter UID filter; not all syscalls or program contents.':
        from .capture_facts import collector_content
        result=copy.deepcopy(full)
        result['metadata']=collector_content(result['metadata'],event.operation)
        if result['metadata'].get('decision_scope')=='group; not per-operation clearance':
            result['metadata']['decision_scope']='group'
        return result
    if event.source!='viztracer':return full
    metadata=full.get('metadata',{})
    if metadata.get('scope')!=KNOWN_SCOPE or metadata.get('limitations')!=KNOWN_LIMITS:return full
    arguments=metadata.get('input_arguments_repr')
    steps=metadata.get('assignment_steps')
    output=metadata.get('return_value_repr')
    if (not isinstance(arguments,dict) or not all(isinstance(v,str) for v in arguments.values())
            or not isinstance(steps,list) or not all(isinstance(s,str) for s in steps)
            or (output is not None and not isinstance(output,str))):return full
    values=list(arguments.values())+([output] if isinstance(output,str) else [])
    parts=[]
    for step in steps:
        match=ASSIGNMENT.fullmatch(step)
        parts.append((match.group(1),match.group(2)) if match else (None,step))
        values.append(match.group(2) if match else step)
    counts=Counter(values)
    table={};ids={}
    for value in values:
        if len(value)>=48 and counts[value]>1 and value not in ids:
            key='v'+str(len(ids)+1);ids[value]=key;table[key]=value
    def ref(value):
        return {'value_ref':ids[value]} if isinstance(value,str) and value in ids else value
    compressed_steps=[]
    for original,(prefix,value) in zip(steps,parts):
        if prefix is not None and value in ids:compressed_steps.append({'prefix':prefix,'value_ref':ids[value]})
        else:compressed_steps.append(ref(original))
    result={'format':'mop.function.v1','operation':event.operation,'source':event.source,'phase':event.phase,
            'context':copy.deepcopy(event.context),
            'function':metadata.get('function'),'file':metadata.get('file'),'line':metadata.get('line'),
            'inputs':{key:ref(value) for key,value in arguments.items()},
            'steps':compressed_steps,'output':ref(output),'return_observed':metadata.get('return_observed',False),
            'capture_status':{'selected_functions_only':True,'complete_dataflow':False}}
    if table:
        result['values']=table
        result['encoding']='value_ref'
    consumed=AUDIT_FIELDS|{'function','file','line','input_arguments_repr','assignment_steps','return_value_repr','return_observed'}
    extra={key:value for key,value in metadata.items() if key not in consumed}
    if extra.get('scope')==KNOWN_SCOPE:extra.pop('scope')
    if extra.get('limitations')==KNOWN_LIMITS:extra.pop('limitations')
    for key in ('assignments_omitted','arguments_omitted'):
        if extra.get(key)==0:extra.pop(key)
    if extra:result['extra']=extra
    # Use the compact representation only when it is actually smaller in bytes.
    return result if len(serialized(result).encode())<len(serialized(full).encode()) else full


def restore_values(view):
    """Round-trip contract for the complete arguments, assignment strings and return."""
    table=view.get('values',{})
    def expand(value):
        if isinstance(value,dict) and 'value_ref' in value:
            return value.get('prefix','')+table[value['value_ref']]
        return value
    return ({key:expand(value) for key,value in view['inputs'].items()},
            [expand(step) for step in view['steps']],expand(view['output']))


def project(event, mode='compact'):
    view=_project(event,mode)
    if mode!='compact' or (event.source!='tetragon' and event.operation!='model_fragment'):
        return view
    metadata=view.get('metadata',{})
    priority=('encoding','content_fragment','node','scope','parent','ancestors','process')
    stable={key:metadata[key] for key in priority if key in metadata}
    stable.update({key:value for key,value in metadata.items() if key not in stable})
    result={key:view[key] for key in ('context','source','phase') if key in view}
    result['metadata']=stable
    result.update({key:value for key,value in view.items() if key not in result})
    return result
