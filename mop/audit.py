"""Private, bounded JSONL audit storage; one writer per log path."""
import fcntl
import json
import os
import stat
from pathlib import Path


class AuditLog:
    def __init__(self, path, max_bytes=10 * 1024 * 1024, backups=3):
        if type(max_bytes) is not int or max_bytes < 1024 or type(backups) is not int or backups < 0:
            raise ValueError("audit limits require max_bytes >= 1024 and backups >= 0")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes, self.backups = max_bytes, backups
        self.fd = None
        self.lock_fd = self._open(str(self.path) + ".lock")
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = self._open(self.path)
        except BaseException:
            os.close(self.lock_fd)
            raise

    @staticmethod
    def _open(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("audit path must be an owned regular file without hard links")
            os.fchmod(fd, 0o600)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def write_record(self, record):
        data = (json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n").encode()
        if len(data) > self.max_bytes:
            raise ValueError("audit record exceeds rotation limit")
        if os.fstat(self.fd).st_size + len(data) > self.max_bytes:
            os.close(self.fd)
            self.fd = None
            for index in range(self.backups, 0, -1):
                source = self.path if index == 1 else Path(str(self.path) + "." + str(index - 1))
                target = Path(str(self.path) + "." + str(index))
                if source.exists():
                    os.replace(source, target)
            if self.backups == 0:
                self.path.unlink(missing_ok=True)
            self.fd = self._open(self.path)
        view = memoryview(data)
        while view:
            count = os.write(self.fd, view)
            if count == 0:
                raise OSError("short audit write")
            view = view[count:]

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
