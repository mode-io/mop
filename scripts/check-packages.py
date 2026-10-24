"""Validate release packages without changing the host package installation."""
import json,os,shutil,subprocess,tempfile
from pathlib import Path
import argparse
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Validate Linux packages in isolated prefixes and an APT target root.')
parser.add_argument('--assets',type=Path,default=ROOT/'dist/packages')
args=parser.parse_args();assets=args.assets.resolve()
work=Path(tempfile.mkdtemp(prefix='install-check-',dir=assets));reports=[]
def run(args,**kwargs):
 return subprocess.run(list(map(str,args)),text=True,capture_output=True,timeout=60,**kwargs)
# User install exercises the actual downloader interface with local release fixtures.
fake=work/'tools';fake.mkdir()
(fake/'gh').write_text('''#!/usr/bin/env bash
set -eu
if [ "$1" = auth ]; then exit 0; fi
while [ "$#" -gt 0 ]; do
 case "$1" in --pattern) asset="$2"; shift 2;; --dir) dest="$2"; shift 2;; *) shift;; esac
done
cp "$TEST_ASSETS/$asset" "$dest/$asset"
''');(fake/'gh').chmod(0o755)
env={**os.environ,'PATH':str(fake)+':/usr/bin:/bin:/usr/sbin:/sbin','TEST_ASSETS':str(assets),'MOP_STATE_DIR':str(work/'state')}
prefix=work/'user prefix';command=['bash',assets/'install.sh','--method','user','--prefix',prefix]
result=run(command,env=env);assert result.returncode==0,result.stdout+result.stderr
for name in ('mop','hmop','bmop'):
 result=run([prefix/'bin'/name,'--version'],cwd='/tmp',env=env);assert result.returncode==0,result.stderr
 assert '0.9.4' in result.stdout;reports.append({'test':name+' installed entry point','result':result.stdout.strip()})
result=run(command,env=env);assert result.returncode==0,result.stderr;reports.append({'test':'repeat installation','passed':True})
result=run([prefix/'bin/mop','doctor'],cwd='/tmp',env=env);assert json.loads(result.stdout)['proc'] is True
result=run([prefix/'bin/mop','-b','-n','1','--standalone','--no-tetragon','-p',os.getpid(),'--base-url','http://127.0.0.1:9','--timeout','.1'],cwd='/tmp',env=env)
assert result.returncode==0,result.stderr;reports.append({'test':'live process view from installed core','passed':True})
bad=work/'bad';shutil.copytree(assets,bad,ignore=shutil.ignore_patterns('install-check-*'))
(bad/'mop-0.9.4-linux-any.tar.gz').write_bytes(b'invalid package')
result=run(command[:-1]+[work/'bad-prefix'],env={**env,'TEST_ASSETS':str(bad)})
assert result.returncode!=0 and not (work/'bad-prefix').exists();reports.append({'test':'checksum mismatch rejected before installation','passed':True})
foreign=work/'foreign';(foreign/'bin').mkdir(parents=True);(foreign/'bin/mop').write_text('keep me')
result=run(command[:-1]+[foreign],env=env);assert result.returncode!=0 and (foreign/'bin/mop').read_text()=='keep me'
reports.append({'test':'unrelated command preserved','passed':True})
# Install/remove with the actual APT/dpkg tools in an isolated target root.
root=work/'apt-root';db=root/'var/lib/dpkg';db.mkdir(parents=True)
shutil.copyfile('/var/lib/dpkg/status',db/'status')
for d in ('empty','lists/partial','archives/partial','logs'):(work/d).mkdir(parents=True,exist_ok=True)
config=work/'apt.conf'
config.write_text('\n'.join([
 f'Dir::Etc::parts "{work}/empty";', 'Dir::Etc::main "/dev/null";',
 f'Dir::Etc::sourcelist "{work}/empty/sources.list";',f'Dir::Etc::sourceparts "{work}/empty";',
 f'Dir::State::status "{db}/status";',f'Dir::State::lists "{work}/lists";',
 f'Dir::Cache::archives "{work}/archives";',f'Dir::Log "{work}/logs";',
 f'Dir::State::extended_states "{work}/extended_states";', 'APT::Sandbox::User "root";','Debug::NoLocking "true";',
 f'DPkg::Options {{ "--root={root}"; "--admindir={db}"; "--no-triggers"; }};',
]))
apt_env={**env,'APT_CONFIG':str(config)}
result=run(['unshare','-Ur','apt-get','install','-y',assets/'mop_0.9.4_all.deb'],env=apt_env)
(assets/'apt-install.log').write_text(result.stdout+result.stderr)
assert result.returncode==0,result.stdout+result.stderr
result=run([root/'usr/bin/mop','--version'],env=env);assert result.returncode==0,result.stderr
reports.append({'test':'APT install in isolated root, host Python dependencies','passed':True})
result=run(['unshare','-Ur','dpkg','--root='+str(root),'--admindir='+str(db),'--no-triggers','--pre-invoke=','--post-invoke=','--purge','mop'],env=env)
assert result.returncode==0 and not (root/'usr/bin/mop').exists(),result.stderr
reports.append({'test':'dpkg removal in isolated root','passed':True})
(assets/'validation.json').write_text(json.dumps(reports,indent=2));print(json.dumps(reports,indent=2))
