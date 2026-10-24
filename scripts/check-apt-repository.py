"""Install from a signed APT source in an isolated target root; preserve the host."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def check(url,keyring,expect_failure=False):
    work=Path(tempfile.mkdtemp(prefix='apt-source-',dir=ROOT/'artifacts'))
    target=work/'root';database=target/'var/lib/dpkg';database.mkdir(parents=True)
    shutil.copyfile('/var/lib/dpkg/status',database/'status')
    for name in ('empty','state/lists/partial','cache/archives/partial','logs'):
        (work/name).mkdir(parents=True,exist_ok=True)
    source=work/'mop.sources'
    source.write_text(f'Types: deb\nURIs: {url}\nSuites: ./\nSigned-By: {keyring.resolve()}\n')
    config=work/'apt.conf'
    config.write_text('\n'.join([
        f'Dir::Etc::parts "{work}/empty";', 'Dir::Etc::main "/dev/null";',
        f'Dir::Etc::sourcelist "{source}";',f'Dir::Etc::sourceparts "{work}/empty";',
        f'Dir::State "{work}/state";',f'Dir::State::status "{database}/status";',
        f'Dir::Cache "{work}/cache";',f'Dir::Log "{work}/logs";',
        'APT::Sandbox::User "root";','APT::Update::Error-Mode "any";',
        'Acquire::http::Timeout "20";','Acquire::https::Timeout "20";','Acquire::Retries "0";',
        f'DPkg::Options {{ "--root={target}"; "--admindir={database}"; "--no-triggers"; "--pre-invoke="; "--post-invoke="; }};',
    ]))
    env={**os.environ,'APT_CONFIG':str(config),'MOP_STATE_DIR':str(work/'mop-state'),
         'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}
    def execute(arguments,label):
        result=subprocess.run(arguments,env=env,text=True,capture_output=True,timeout=180)
        (work/(label+'.log')).write_text(result.stdout+result.stderr)
        return result
    update=execute(['unshare','-Ur','apt-get','update'],'update')
    if expect_failure:
        assert update.returncode!=0,'Tampered index was unexpectedly accepted'
        return {'source':url,'tampered_index_rejected':True,'work':str(work)}
    assert update.returncode==0,update.stdout+update.stderr
    install=execute(['unshare','-Ur','apt-get','install','-y','mop'],'install')
    assert install.returncode==0,install.stdout+install.stderr
    versions={}
    for name in ('mop','hmop','bmop'):
        result=execute([str(target/'usr/bin'/name),'--version'],name)
        assert result.returncode==0,result.stderr
        versions[name]=result.stdout.strip()
    remove=execute(['unshare','-Ur','apt-get','remove','-y','mop'],'remove')
    assert remove.returncode==0 and not (target/'usr/bin/mop').exists(),remove.stdout+remove.stderr
    return {'source':url,'signature_verified_by_apt':True,'installed':versions,'removed':True,'work':str(work)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='https://github.com/mode-io/mop/releases/download/apt/')
    parser.add_argument('--keyring',type=Path,default=ROOT/'dist/apt/modeio-mop.gpg')
    parser.add_argument('--expect-failure',action='store_true')
    args=parser.parse_args()
    report=check(args.url,args.keyring,args.expect_failure)
    print(json.dumps(report,indent=2))
