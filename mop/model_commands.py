"""User commands for model manifests, revisions and review rules."""
import argparse
import asyncio
import json
import os
from pathlib import Path
from .model_slots import Registry, revision

def default_registry():
    from .config import DEFAULT_CONFIG, read_json
    config=read_json(DEFAULT_CONFIG)
    registry=Registry()
    slot=registry.default['models'][0]
    slot.update(endpoint=os.environ.get('MOP_BASE_URL',config.get('base_url',slot['endpoint'])),
                model=os.environ.get('MOP_MODEL',config.get('model',slot['model'])),
                allow_remote=config.get('allow_remote',False))
    return registry

async def probe(slot):
    from .classification import ClassificationProvider
    from .core import Event
    provider=ClassificationProvider(slot['endpoint'],slot['model'],api_key=os.environ.get('MOP_API_KEY',''),allow_remote=slot['allow_remote'])
    try:
        import urllib.request
        from .classification import NoRedirect
        base=slot['endpoint'].rstrip('/')
        if base.endswith('/v1'):base=base[:-3]
        def hosted_models():
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            request=urllib.request.Request(base+'/v1/models',headers={'Authorization':'Bearer '+provider.api_key} if provider.api_key else {})
            with opener.open(request,timeout=3) as response:raw=response.read(65537)
            if len(raw)>65536:raise ValueError('Model discovery response too large')
            return {m['id'] for m in json.loads(raw)['data']}
        if slot['model'] not in await asyncio.to_thread(hosted_models):raise ValueError('Configured model is not served by this endpoint')
        event=Event('task_discovered','proc-poll',os.getpid(),os.getpid(),'mop',metadata={'command':list(__import__('sys').argv),'uid':os.getuid()})
        verdict=await asyncio.wait_for(provider.infer(event),slot['budget_ms']/1000)
        if verdict.category=='unknown':raise ValueError('Model probe returned unknown')
        return {'name':slot['name'],'status':'reachable','category':verdict.category}
    finally:await provider.aclose()

def install_placeholder(registry,name):
    current=registry.read()
    core=next(s for s in current['models'] if s['role']=='core')
    if name=='jev-core':
        asyncio.run(probe(core));return core
    existing=next((s for s in current['models'] if s['name']==name),None)
    if existing:
        asyncio.run(probe(existing));return existing
    slot=dict(core,name=name,role='specialist',state='shadow',sources=[],version=('placeholder/'+core['version'])[:256])
    from .model_slots import validate
    validate({'models':current['models']+[slot],'rules':current['rules']})
    asyncio.run(probe(slot))
    def change(value):
        if next(s for s in value['models'] if s['role']=='core') != core:raise ValueError('Core changed while connecting; reload the panel')
        if any(s['name']==name for s in value['models']):raise ValueError('Slot changed while connecting; reload the panel')
        value['models'].append(slot)
    registry.update(change,'model_install_placeholder')
    return slot


def main(argv):
    p=argparse.ArgumentParser(prog='mop '+argv[0]);sub=p.add_subparsers(dest='action')
    sub.add_parser('list')
    if argv[0]=='models':
        add=sub.add_parser('add');add.add_argument('manifest',type=Path)
        install=sub.add_parser('install');install.add_argument('name',choices=['jev-core','guard-privacy','guard-permission','guard-content','guard-compliance'])
        for name in ('active','shadow','disable','probe'):
            command=sub.add_parser(name);command.add_argument('name')
        sub.add_parser('versions')
        rollback=sub.add_parser('rollback');rollback.add_argument('revision')
    else:
        add=sub.add_parser('add');add.add_argument('id');add.add_argument('text')
        for name in ('enable','disable','remove'):
            command=sub.add_parser(name);command.add_argument('id')
    args=p.parse_args(argv[1:]);registry=default_registry()
    try:
        current=registry.read()
        if args.action in (None,'list'):
            if argv[0]=='rules':
                for rule in current['rules']:print('%s  %-8s %s' % (rule['id'],'enabled' if rule['enabled'] else 'disabled',rule['text']))
                if not current['rules']:print('No custom rules. Add one with: mop rules add ID "Review policy"')
            else:
                print('MODEL SLOTS  |  OBSERVE  |  revision '+revision(current))
                for slot in current['models']:print('%-24s %-10s %-10s %s  %s' % (slot['name'],slot['role'],slot['state'],slot['version'],slot['endpoint']))
                print('Register a hosted model: mop models add manifest.json')
            return 0
        if argv[0]=='models':
            if args.action=='install':
                value=install_placeholder(registry,args.name)
                print('Connected '+args.name+' to '+value['model']+' (placeholder, '+value['state']+').')
                return 0
            if args.action=='versions':
                print('Current: '+revision(current))
                for path in sorted((registry.root/'versions').glob('*.json')):print(path.stem)
                return 0
            if args.action=='rollback':
                value=json.loads((registry.root/'versions'/(args.revision+'.json')).read_text()) if __import__('re').fullmatch('[0-9a-f]{12}',args.revision) else None
                if value is None:raise ValueError('Invalid revision')
                from .model_slots import validate
                validate(value)
                for slot in value['models']:
                    if slot['state']!='disabled':asyncio.run(probe(slot))
                registry.rollback(args.revision)
            elif args.action=='add':
                if args.manifest.stat().st_size>8192:raise ValueError('Manifest too large')
                slot=json.loads(args.manifest.read_text());preview=json.loads(json.dumps(current))
                def change(value):
                    value['models']=[s for s in value['models'] if s['name']!=slot['name'] and not (slot['role']=='core' and s['role']=='core')]+[slot]
                change(preview)
                from .model_slots import validate
                validate(preview)
                if slot['state']!='disabled':asyncio.run(probe(slot))
                registry.update(change,'model_register')
            else:
                slot=next((s for s in current['models'] if s['name']==args.name),None)
                if slot is None:raise ValueError('Unknown model slot')
                if args.action=='probe':print(json.dumps(asyncio.run(probe(slot)),indent=2));return 0
                state={'active':'active','shadow':'shadow','disable':'disabled'}[args.action]
                if state!='disabled':asyncio.run(probe(slot))
                def change(value):
                    next(s for s in value['models'] if s['name']==args.name)['state']=state
                registry.update(change,'model_'+state)
        else:
            def change(value):
                if args.action=='add':
                    value['rules']=[r for r in value['rules'] if r['id']!=args.id]+[{'id':args.id,'text':args.text,'enabled':True}]
                else:
                    rule=next((r for r in value['rules'] if r['id']==args.id),None)
                    if rule is None:raise ValueError('Unknown rule')
                    if args.action=='remove':value['rules'].remove(rule)
                    else:rule['enabled']=args.action=='enable'
            registry.update(change,'rule_'+args.action)
        print('Saved revision '+revision(registry.read())+'. Running observers reload automatically.')
        return 0
    except Exception as error:
        print('MOP: '+(str(error) if isinstance(error,ValueError) else type(error).__name__))
        return 2
