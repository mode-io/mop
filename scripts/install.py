#!/usr/bin/env python3
"""One entry point for MOP, optional system tools, and measured capabilities."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ECAPTURE_VERSION = '2.8.2'
ECAPTURE_NAME = 'ecapture-v2.8.2-linux-amd64.tar.gz'
ECAPTURE_SHA = '7a064da2708b0c179907f5f8603d7fb74ad8d5a7571165b09ab9263dcca67ae2'
TETRAGON_NAME = 'tetragon-v1.7.0-amd64.tar.gz'
TETRAGON_SHA = '67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772'
SYSTEM_BINARY = Path('/opt/mop-tools/ecapture-2.8.2/ecapture')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def content_command(rollback=False):
    result=['sudo','-n','/usr/bin/python3','-I',ROOT/'scripts/install-content-service.py',
            '--uid',os.getuid(),'--gid',os.getgid(),'--agent',ROOT/'scripts/content-agent.py']
    return result+(['--rollback'] if rollback else ['--tls'])


def command(argv, timeout=60):
    return subprocess.run(list(map(str, argv)), check=True, capture_output=True,
                          text=True, timeout=timeout)


def service_active(name):
    try:return subprocess.run(['systemctl','is-active','--quiet',name],timeout=5).returncode==0
    except (OSError,subprocess.TimeoutExpired):return False


def model_status(allow_remote=False):
    config=ROOT/'config/mop.json'
    if not config.exists():config=ROOT/'mop/default.json'
    try:
        settings=json.loads(config.read_text())
        import urllib.parse
        url=settings.get('base_url','http://127.0.0.1:18936').rstrip('/')
        parsed=urllib.parse.urlsplit(url)
        if (not allow_remote and parsed.hostname not in {'127.0.0.1','localhost','::1'}) or parsed.scheme not in {'http','https'} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/','/v1'):
            return {'status':'not_probed','reason':'non_loopback_or_credentialed_endpoint'}
        if url.endswith('/v1'):url=url[:-3]
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open(url+'/health',timeout=3) as response:
            return {'status':'ready' if response.status==200 else 'unavailable','endpoint':url}
    except Exception:return {'status':'unavailable'}


def download(cache, name, url, digest, offline=False):
    destination=cache/name
    for candidate in (destination,ROOT/'.runtime'/name,
                      ROOT/'.runtime/tetragon/verified.tar.gz' if name==TETRAGON_NAME else destination):
        if candidate.is_file() and not candidate.is_symlink():
            if hashlib.sha256(candidate.read_bytes()).hexdigest()==digest:return candidate
    if offline:raise ValueError('Verified archive unavailable in offline cache: '+name)
    if not url.startswith('https://github.com/'):
        raise ValueError('Release URL must use the pinned HTTPS origin')
    fd,tmp=tempfile.mkstemp(dir=cache,prefix='.download-')
    try:
        with os.fdopen(fd,'wb') as output,urllib.request.urlopen(url,timeout=30) as response:
            total=0;sha=hashlib.sha256()
            while True:
                data=response.read(1024*1024)
                if not data:break
                total+=len(data)
                if total>512*1024*1024:raise ValueError('Release archive exceeds size limit')
                output.write(data);sha.update(data)
        if sha.hexdigest()!=digest:raise ValueError('Release checksum mismatch: '+name)
        os.replace(tmp,destination)
        return destination
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def write_report(path, report):
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.report-')
    try:
        with os.fdopen(fd,'w') as output:json.dump(report,output,indent=2);output.write('\n')
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def inspect():
    return {'platform':platform.system(),'architecture':platform.machine(),
            'kernel':platform.release(),'btf_available':Path('/sys/kernel/btf/vmlinux').is_file(),
            'tetragon':{'status':'active' if service_active('mop-tetragon.service') else 'unavailable'},
            'ecapture':{'status':'installed' if SYSTEM_BINARY.is_file() else 'missing'},
            'content_collector':{'status':'active' if service_active('mop-content-%d.service' % os.getuid()) else 'unavailable'},
            'model':model_status()}


def model_url(value):
    from urllib.parse import urlsplit
    try:
        url=urlsplit(value)
        port=url.port
    except ValueError:
        raise argparse.ArgumentTypeError('Use an HTTP(S) model endpoint, such as http://127.0.0.1:18936')
    if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise argparse.ArgumentTypeError('Use an HTTP(S) endpoint without credentials, query or fragment')
    return value.rstrip('/')


def configure_model(url):
    path=ROOT/'config/mop.json'
    settings=json.loads((path if path.exists() else ROOT/'mop/default.json').read_text())
    settings['base_url']=url
    path.parent.mkdir(parents=True,exist_ok=True)
    write_report(path,settings)


def ensure_python(offline=False, core_only=False):
    modules='import venv,curses' + ('' if shutil.which('uv') else ',ensurepip')
    if subprocess.run(['/usr/bin/python3','-c',modules],capture_output=True).returncode==0:return
    if core_only or offline or not shutil.which('apt-get'):
        raise RuntimeError('Install Python 3.10+ with venv, ensurepip and curses, then rerun setup')
    if subprocess.run(['sudo','-n','true'],capture_output=True).returncode:
        subprocess.run(['sudo','-v'],check=True)
    print('Installing Python environment support...',flush=True)
    command(['sudo','-n','apt-get','update'],timeout=300)
    command(['sudo','-n','apt-get','install','-y','--no-install-recommends','python3-venv'],timeout=300)
    command(['/usr/bin/python3','-c',modules])


def command_entrypoints(core_only=False, system_bin=Path('/usr/local/bin')):
    user_bin=Path.home()/'.local/bin'
    paths={Path(p).expanduser() for p in os.environ.get('PATH','').split(os.pathsep) if p}
    if user_bin in paths:return 'mop'
    if core_only or system_bin not in paths:return str(user_bin/'mop')
    targets=[(system_bin/name,ROOT/'scripts'/name) for name in ('mop','hmop','bmop','mop-network')]
    # Preserve unrelated commands, including links from other installations.
    for target,source in targets:
        if (target.exists() or target.is_symlink()) and not (target.is_symlink() and target.resolve()==source.resolve()):
            return str(user_bin/'mop')
    for target,source in targets:
        if not target.is_symlink():command(['sudo','-n','ln','-s',source,target])
    return 'mop'


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='inspect without installing or loading probes')
    parser.add_argument('--core-only',action='store_true',help='install user-level MOP without sudo or probes')
    parser.add_argument('--offline',action='store_true',help='use only already cached Python packages and release archives')
    parser.add_argument('--rollback',action='store_true',help='undo collector changes made by the last installation')
    parser.add_argument('--model-url',type=model_url,help='connect a running vLLM-Jev service')
    args=parser.parse_args(argv)
    if args.model_url and (args.check or args.rollback):parser.error('--model-url is for installation')
    if args.check:
        report=inspect();previous=ROOT/'.runtime/installation/report.json'
        if previous.exists():report['last_installation']=json.loads(previous.read_text())
        print(json.dumps(report,indent=2));return 0
    if platform.system()!='Linux' or sys.version_info<(3,10):parser.error('Linux and Python 3.10+ are required')
    if os.getuid()==0:parser.error('Run as the normal user; only system-tool steps request sudo')
    work=ROOT/'.runtime/installation';work.mkdir(parents=True,exist_ok=True,mode=0o700)
    lock=os.open(work/'install.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:parser.error('Another MOP installation is running')
    report=inspect();report.update(schema=1,started_at=time.time(),uid=os.getuid(),created_system_tool=False)
    report_path=work/'report.json'
    try:
        if args.rollback:
            old=json.loads(report_path.read_text())
            if old.get('changed_content_service'):
                old['content_rollback']=json.loads(command(content_command(True)).stdout)
                old['changed_content_service']=False
            if old.get('created_system_tool'):
                old['tool_rollback']=json.loads(command(['sudo','-n','/usr/bin/python3','-I',ROOT/'scripts/install-system-tools.py','--rollback']).stdout)
                old['created_system_tool']=False
            write_report(report_path,old);print(json.dumps(old,indent=2));return 0
        env=os.environ.copy()
        if args.offline:env.update(UV_OFFLINE='1',PIP_NO_INDEX='1')
        ensure_python(args.offline,args.core_only)
        print('Installing MOP...',flush=True)
        core=subprocess.run(['bash',str(ROOT/'scripts/setup-core.sh')],env=env,capture_output=True,text=True,timeout=300)
        if core.returncode:
            report['core']={'status':'failed','exit_code':core.returncode}
            (work/'core.log').write_text(core.stdout+core.stderr);(work/'core.log').chmod(0o600)
            raise RuntimeError('Core setup failed; see .runtime/installation/core.log')
        report['core']={'status':'ready'}
        if not args.core_only:
            if platform.machine() not in {'x86_64','amd64'}:
                report['system_tools']={'status':'unsupported_architecture'}
            else:
                # sudo may prompt once in an interactive terminal; never capture a password.
                if subprocess.run(['sudo','-n','true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
                    subprocess.run(['sudo','-v'],check=True)
                cache=work/'cache';cache.mkdir(exist_ok=True,mode=0o700)
                print('Verifying the pinned eCapture release...',flush=True)
                archive=download(cache,ECAPTURE_NAME,
                    'https://github.com/gojue/ecapture/releases/download/v2.8.2/'+ECAPTURE_NAME,ECAPTURE_SHA,args.offline)
                result=command(['sudo','-n','/usr/bin/python3','-I',ROOT/'scripts/install-system-tools.py','--archive',archive])
                installed=json.loads(result.stdout);report['ecapture']=installed
                report['created_system_tool']=installed['created']
                command([SYSTEM_BINARY,'--version'])
                unit=Path('/etc/systemd/system/mop-tetragon.service')
                if unit.exists():
                    report['tetragon']={'status':'active' if service_active('mop-tetragon.service') else 'inactive','reused':True}
                else:
                    report['tetragon']={'status':'optional_not_installed'}
                if report['btf_available']:
                    missing=[package for name,package in (('bpftrace','bpftrace'),('curl','curl'),('openssl','openssl'),('nm','binutils')) if not shutil.which(name)]
                    if subprocess.run(['/usr/bin/python3','-I','-c','import hpack'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:missing.append('python3-hpack')
                    if missing:
                        if args.offline:raise RuntimeError('Missing offline dependencies: '+', '.join(missing))
                        if not shutil.which('apt-get'):raise RuntimeError('Install system packages: '+', '.join(missing))
                        print('Installing missing system packages...',flush=True)
                        command(['sudo','-n','apt-get','install','-y','--no-install-recommends','-o','DPkg::Lock::Timeout=30']+missing,timeout=300)
                    print('Installing the bounded content collector...',flush=True)
                    report['content_collector']=json.loads(command(content_command()).stdout)
                    report['changed_content_service']=report['content_collector']['status']=='installed'
                    print('Checking ordinary stdout and local HTTPS clients...',flush=True)
                    result=command([ROOT/'.venv/bin/python',ROOT/'scripts/check-content-capture.py','--work',work],timeout=60)
                    checks=json.loads(result.stdout);report['content_validation']=checks
                    required=('stdout','python_tls_request','python_tls_response','curl_tls_request','curl_tls_response','chunked_response','sse_response','request_response_linked','sse_complete')
                    if not all(checks.get(key) is True for key in required):
                        raise RuntimeError('Content self-test failed; see the installation report')
                    report['default_stdout_capture']={'status':'verified','bytes_per_write':3072}
                    report['default_tls_capture']={'status':'verified','bytes_per_call':3072,'protocols':['HTTP/1 Content-Length','HTTP/1 chunked','SSE'],'library':'system libssl.so.3','additional_adapters':'see mop-network status'}
                    print('Setting up authenticated loopback protocol adapters...',flush=True)
                    network=command([ROOT/'.venv/bin/python',ROOT/'scripts/setup-network.py']+(['--offline'] if args.offline else []),timeout=240)
                    report['network_proxy']=json.loads(network.stdout)
                else:report['content_validation']={'status':'not_verified','reason':'missing_btf'}
        if args.model_url:configure_model(args.model_url)
        launch=command_entrypoints(args.core_only or report.get('system_tools',{}).get('status')=='unsupported_architecture')
        report['launch_command']=launch
        report['model']=model_status(allow_remote=bool(args.model_url))
        report['status']='core_ready' if args.core_only else ('ready_with_limits' if report.get('default_tls_capture',{}).get('status')=='verified' and report['model']['status']=='ready' else 'degraded')
        report['finished_at']=time.time();write_report(report_path,report)
        print('\nInstalled. Start with: '+launch)
        if report['model']['status']=='ready':print('AI review: connected to the model.')
        elif report['model']['status']=='not_probed':print('Model endpoint configured. Run mop check to test AI review.')
        else:print('AI review needs a running model. See docs/jev-2b-batching.md.')
        print('Collector status: mop-network status')
        print('Installation details: '+str(report_path))
        return 0 if report['status'] in ('core_ready','ready_with_limits') else 2
    except Exception as error:
        report['status']='failed';report['error']=type(error).__name__+': '+str(error)
        if report.get('changed_content_service'):
            try:report['content_rollback']=json.loads(command(content_command(True)).stdout)
            except Exception as rollback_error:report['content_rollback']={'status':'failed','reason':type(rollback_error).__name__}
        if report.get('created_system_tool'):
            try:report['rollback']=json.loads(command(['sudo','-n','/usr/bin/python3','-I',ROOT/'scripts/install-system-tools.py','--rollback']).stdout)
            except Exception as rollback_error:report['rollback']={'status':'failed','reason':type(rollback_error).__name__}
        write_report(report_path,report)
        print(report['error'],file=sys.stderr);return 1
    finally:
        os.close(lock)


if __name__=='__main__':raise SystemExit(main())
