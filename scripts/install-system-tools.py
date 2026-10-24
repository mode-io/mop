#!/usr/bin/env python3
"""Privileged, atomic installation of pinned tools. Never enables capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile

VERSION = '2.8.2'
SHA256 = '7a064da2708b0c179907f5f8603d7fb74ad8d5a7571165b09ab9263dcca67ae2'
BASE = Path('/opt/mop-tools')


def safe_directory(path):
    path.mkdir(mode=0o755, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('System directory is not root-owned and immutable to other users')


def install(archive, destination=BASE):
    safe_directory(destination)
    target = destination / ('ecapture-' + VERSION)
    receipt = target / 'receipt.json'
    if target.exists():
        safe_directory(target)
        if not receipt.is_file() or receipt.is_symlink():
            raise ValueError('Refusing to overwrite an unmanaged installation')
        old = json.loads(receipt.read_text())
        binary = target / 'ecapture'
        if old.get('archive_sha256') != SHA256 or binary.is_symlink():
            raise ValueError('Existing tool does not match the pinned release')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != old.get('binary_sha256'):
            raise ValueError('Installed binary integrity check failed')
        if binary.stat().st_uid!=0 or binary.stat().st_mode&0o022:
            raise ValueError('Installed binary permissions are unsafe')
        return {'status':'reused','binary':str(binary),'version':VERSION,'created':False}
    staging = Path(tempfile.mkdtemp(prefix='.install-', dir=destination))
    try:
        # Copy into a private root-owned staging area before verification/extraction.
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as source, (staging/'archive.tar.gz').open('xb') as output:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 64*1024*1024:
                raise ValueError('Invalid release archive')
            copied=0
            while True:
                chunk=source.read(1024*1024)
                if not chunk:break
                copied+=len(chunk)
                if copied>64*1024*1024:raise ValueError('Release archive grew beyond its size limit')
                output.write(chunk)
        blob=staging/'archive.tar.gz'
        if hashlib.sha256(blob.read_bytes()).hexdigest()!=SHA256:
            raise ValueError('Release checksum mismatch')
        with tarfile.open(blob,'r:gz') as tar:
            member=tar.getmember('ecapture-v'+VERSION+'-linux-amd64/ecapture')
            if not member.isfile() or not 0 < member.size <= 192*1024*1024:
                raise ValueError('Release binary is not an ordinary bounded file')
            with tar.extractfile(member) as source,(staging/'ecapture').open('xb') as output:
                shutil.copyfileobj(source,output)
        binary=staging/'ecapture';binary.chmod(0o755)
        blob.unlink()
        (staging/'receipt.json').write_text(json.dumps({
            'owner':'mop-installer','version':VERSION,'archive_sha256':SHA256,
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
        staging.chmod(0o755)
        os.replace(staging,target)
        return {'status':'installed','binary':str(target/'ecapture'),'version':VERSION,'created':True}
    finally:
        if staging.exists():shutil.rmtree(staging)


def rollback(destination=BASE):
    target=destination/('ecapture-'+VERSION)
    if not target.exists():return {'status':'absent'}
    safe_directory(destination);safe_directory(target)
    receipt=target/'receipt.json';binary=target/'ecapture'
    if receipt.is_symlink() or binary.is_symlink():raise ValueError('Unsafe tool path')
    record=json.loads(receipt.read_text())
    if record.get('owner')!='mop-installer' or record.get('archive_sha256')!=SHA256:
        raise ValueError('Refusing to remove an unmanaged tool')
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=record.get('binary_sha256'):
        raise ValueError('Tool was modified after installation; preserving it')
    if set(p.name for p in target.iterdir())!={'ecapture','receipt.json'}:
        raise ValueError('Additional files found; preserving installation')
    shutil.rmtree(target)
    return {'status':'removed'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path);p.add_argument('--rollback',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0:p.error('System tool installation requires administrator privileges')
    if not a.rollback and a.archive is None:p.error('--archive is required')
    print(json.dumps(rollback() if a.rollback else install(a.archive)))


if __name__=='__main__':main()
