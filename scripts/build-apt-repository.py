"""Build a signed flat APT repository suitable for GitHub release assets."""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
UID='modeio MOP packages <91329273+Egbertjing@users.noreply.github.com>'


def build(packages, output, key_home, initialize=False):
    output=output.resolve();key_home=key_home.resolve()
    output.mkdir(parents=True,exist_ok=True);key_home.mkdir(parents=True,exist_ok=True,mode=0o700)
    key_home.chmod(0o700)
    gpg=['gpg','--batch','--homedir',str(key_home)]
    listed=subprocess.run(gpg+['--with-colons','--list-secret-keys',UID],capture_output=True,text=True)
    fingerprints=[line.split(':')[9] for line in listed.stdout.splitlines() if line.startswith('fpr:')]
    if not fingerprints:
        if not initialize:raise RuntimeError('No archive key; pass --initialize-key once or restore the private signing key')
        subprocess.run(gpg+['--pinentry-mode','loopback','--passphrase','','--quick-generate-key',UID,'rsa3072','sign','2y'],check=True)
        listing=subprocess.check_output(gpg+['--with-colons','--list-secret-keys',UID],text=True)
        fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    if len(fingerprints)!=1:raise RuntimeError('Expected exactly one dedicated archive signing key')
    key=fingerprints[0]
    package_paths=sorted(packages.glob('*.deb'))
    if not package_paths:raise RuntimeError('Build at least one DEB package first')
    # Keep each versioned package available; do not replace a published version in place.
    for package in package_paths:
        destination=output/package.name
        if destination.exists() and destination.read_bytes()!=package.read_bytes():
            raise RuntimeError('Refusing to replace an existing versioned package: '+package.name)
        shutil.copyfile(package,destination)
    index=subprocess.check_output(['apt-ftparchive','packages','.'],cwd=output)
    (output/'Packages').write_bytes(index)
    (output/'Packages.gz').write_bytes(gzip.compress(index,mtime=0))
    now=datetime.now(timezone.utc)
    release=['Origin: modeio','Label: MOP','Suite: stable','Codename: stable',
             'Architectures: amd64 arm64 all','Description: modeio MOP Linux packages',
             'Date: '+format_datetime(now,usegmt=True),
             'Valid-Until: '+format_datetime(now+timedelta(days=180),usegmt=True),'SHA256:']
    for name in ('Packages','Packages.gz'):
        raw=(output/name).read_bytes();release.append(f' {hashlib.sha256(raw).hexdigest()} {len(raw)} {name}')
    (output/'Release').write_text('\n'.join(release)+'\n')
    subprocess.run(gpg+['--yes','--local-user',key,'--armor','--clearsign','--output',str(output/'InRelease'),str(output/'Release')],check=True)
    subprocess.run(gpg+['--yes','--local-user',key,'--armor','--detach-sign','--output',str(output/'Release.gpg'),str(output/'Release')],check=True)
    public_key=subprocess.check_output(gpg+['--export',key]);(output/'modeio-mop.gpg').write_bytes(public_key)
    setup=(ROOT/'packaging/setup-apt.sh.in').read_text().replace('@KEY_SHA256@',hashlib.sha256(public_key).hexdigest())
    (output/'setup-apt.sh').write_text(setup);(output/'key-fingerprint.txt').write_text(key+'\n')
    subprocess.run(['gpgv','--keyring',str(output/'modeio-mop.gpg'),str(output/'InRelease')],check=True)
    print('Archive key fingerprint: '+key)
    print('Repository: '+str(output))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packages',type=Path,default=ROOT/'dist/packages')
    p.add_argument('--output',type=Path,default=ROOT/'dist/apt')
    p.add_argument('--key-home',type=Path,default=ROOT/'.runtime/release-signing/gnupg')
    p.add_argument('--initialize-key',action='store_true')
    args=p.parse_args();build(args.packages,args.output,args.key_home,args.initialize_key)
