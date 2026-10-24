"""Build relocatable Linux core packages without changing the host installation."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def build(out, nfpm):
    version = re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"', (ROOT/'pyproject.toml').read_text(), re.M)[1]
    out = out.resolve(); out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mop-package-') as temporary:
        stage = Path(temporary)/'root'; code = stage/'share/modeio-mop/mop'
        code.mkdir(parents=True); (stage/'bin').mkdir()
        for path in sorted((ROOT/'mop').rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.json') and '__pycache__' not in path.parts:
                dest=code/path.relative_to(ROOT/'mop');dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(path,dest);dest.chmod(0o644)
        for name in ('mop','hmop','bmop'):
            path=stage/'bin'/name;shutil.copyfile(ROOT/'packaging/launcher.py',path);path.chmod(0o755)
        # A deterministic, portable core archive; optional tracing libraries are not vendored.
        archive=out/f'mop-{version}-linux-any.tar.gz'
        with archive.open('wb') as raw, gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w') as tar:
            for path in sorted(stage.rglob('*')):
                if not path.is_file():continue
                info=tar.gettarinfo(str(path),str(path.relative_to(stage)))
                info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0
                with path.open('rb') as stream:tar.addfile(info,stream)
        config={'name':'mop','arch':'all','platform':'linux','version':version,'release':'1',
                'maintainer':'Egbertjing <91329273+Egbertjing@users.noreply.github.com>',
                'description':'modeio all-in-one process monitor with AI security review',
                'homepage':'https://github.com/mode-io/mop','license':'Proprietary',
                'section':'utils','priority':'optional','contents':[
                    {'src':str(path),'dst':'/usr/'+str(path.relative_to(stage)),
                     'file_info':{'mode':path.stat().st_mode & 0o777,'mtime':'2026-10-24T00:00:00Z'}}
                    for path in sorted(stage.rglob('*')) if path.is_file()],
                'overrides':{'deb':{'depends':['python3 (>= 3.10)']},
                             'rpm':{'depends':['python3 >= 3.10']},
                             'archlinux':{'depends':['python>=3.10']}},
                'rpm':{'arch':'noarch'},'archlinux':{'arch':'any','packager':'Egbertjing <91329273+Egbertjing@users.noreply.github.com>'}}
        config_path=Path(temporary)/'nfpm.json';config_path.write_text(json.dumps(config))
        names={'deb':f'mop_{version}_all.deb','rpm':f'mop-{version}-1.noarch.rpm',
               'archlinux':f'mop-{version}-1-any.pkg.tar.zst'}
        assets=[archive.name]
        for kind,name in names.items():
            subprocess.run([nfpm,'package','--config',str(config_path),'--packager',kind,'--target',str(out/name)],check=True)
            assets.append(name)
        shutil.copyfile(ROOT/'packaging/install.sh',out/'install.sh');assets.append('install.sh')
        wheel=out/f'modeio_mop-{version}-py3-none-any.whl'
        if wheel.is_file():assets.append(wheel.name)
        manifest={'version':version,'platform':'linux','minimum_python':'3.10',
                  'scope':'Core terminal, process observation and configured model review. Collectors and model weights are installed separately.',
                  'files':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in sorted(assets)}}
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');assets.append('manifest.json')
        (out/'SHA256SUMS').write_text(''.join(hashlib.sha256((out/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in sorted(assets)))
        print(json.dumps(manifest,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'dist/packages')
    parser.add_argument('--nfpm',default=shutil.which('nfpm'))
    args=parser.parse_args()
    if not args.nfpm:parser.error('Install nFPM 2.48.0 or pass --nfpm PATH')
    build(args.output,args.nfpm)
