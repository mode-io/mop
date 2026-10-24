"""Conservative pre-use artifact checks. Findings never assert actual execution."""
import ast
import os
import re


def literal(value):
    if not isinstance(value,str) or len(value)>4096:return None
    try:return ast.literal_eval(value)
    except (ValueError,SyntaxError,RecursionError,MemoryError):return None


def where_offset(query):
    """Find a top-level WHERE in a restricted single SQL statement."""
    index=0;depth=0;found=None
    while index<len(query):
        char=query[index]
        if char in "'\"`":
            quote=char;index+=1
            while index<len(query):
                if query[index]=='\\':return None
                if query[index]==quote:
                    if index+1<len(query) and query[index+1]==quote:index+=2;continue
                    index+=1;break
                index+=1
            else:return None
            continue
        if query.startswith('--',index):
            end=query.find('\n',index);index=len(query) if end<0 else end+1;continue
        if query.startswith('/*',index):
            end=query.find('*/',index+2)
            if end<0:return None
            index=end+2;continue
        if char=='(':depth+=1
        if char==')':
            depth-=1
            if depth<0:return None
        if char==';' and query[index+1:].strip():return None
        match=re.match(r'[A-Za-z_][A-Za-z_0-9]*',query[index:])
        if match:
            if depth==0 and match.group().upper()=='WHERE':found=index
            index+=len(match.group());continue
        index+=1
    return found if depth==0 else None


def deletion_target(value):
    if isinstance(value,dict) and value.get('tool') in ('delete_directory','rmtree'):
        args=value.get('arguments')
        return args.get('path') if isinstance(args,dict) and isinstance(args.get('path'),str) else None
    if isinstance(value,list) and all(isinstance(x,str) for x in value) and value and os.path.basename(value[0])=='rm':
        flags=[x for x in value[1:] if x.startswith('-')]
        recursive=any(x=='--recursive' or (not x.startswith('--') and ('r' in x or 'R' in x)) for x in flags)
        targets=[x for x in value[1:] if not x.startswith('-')]
        if recursive and len(targets)==1:return targets[0]
    return None


def findings(event):
    if event.source!='viztracer':return []
    metadata=event.metadata
    if not metadata.get('return_observed'):return []
    arguments=metadata.get('input_arguments_repr',{})
    if not isinstance(arguments,dict):return []
    output=literal(metadata.get('return_value_repr'))
    result=[]
    for name,representation in list(arguments.items())[:16]:
        original=literal(representation)
        if isinstance(original,str) and isinstance(output,str) and re.match(r'^\s*(DELETE\s+FROM\b|UPDATE\b)',original,re.I):
            offset=where_offset(original)
            if offset is not None and original[offset+5:].strip().strip(';') and output.strip().rstrip(';').strip()==original[:offset].strip():
                result.append({'rule':'destructive_sql_scope_removed','severity':'high_risk',
                    'input_argument':name,'finding':'The returned destructive SQL is the input statement with its top-level WHERE constraint removed.',
                    'scope':'Generated artifact risk; no database execution established.'})
        old_target,new_target=deletion_target(original),deletion_target(output)
        if old_target and old_target.startswith('/') and old_target!='/' and new_target=='/':
            result.append({'rule':'deletion_target_expanded_to_root','severity':'high_risk',
                'input_argument':name,'finding':'A directory-deletion artifact changed its target from a narrower absolute path to filesystem root.',
                'scope':'Generated artifact risk; no deletion established.'})
    return result


def apply(verdict,event):
    matches=findings(event)
    if not matches:return verdict
    verdict.model_assessment={'category':verdict.category,'confidence':verdict.confidence,'probabilities':dict(verdict.probabilities)}
    verdict.rule_findings=matches
    verdict.category='high_risk';verdict.confidence=None;verdict.probabilities={}
    verdict.reason='Deterministic artifact-risk rule matched; model assessment retained separately. No execution or harm is claimed.'
    verdict.provider='vllm-jev+artifact-rules'
    return verdict
