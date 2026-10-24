"""Read-only Linux process snapshots. No command line or environment collection."""
import os
import pwd
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=4096)
def username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def snapshot(root="/proc", all_users=False, threads=False):
    rows, denied = [], 0
    own_uid = os.getuid()
    for path in Path(root).iterdir():
        if not path.name.isdecimal():
            continue
        try:
            uid = path.stat().st_uid
            if not all_users and uid != own_uid:
                continue
            targets = list((path / "task").iterdir()) if threads else [path]
            for target in targets:
                try:
                    raw = (target / "stat").read_text()
                    left, right = raw.index("("), raw.rindex(")")
                    fields = raw[right + 2:].split()
                    rows.append({
                        "pid": int(path.name), "tid": int(target.name), "uid": uid,
                        "comm": raw[left + 1:right], "state": fields[0],
                        "user": username(uid), "priority": int(fields[15]),
                        "nice": int(fields[16]), "vsize": int(fields[20]),
                        "ppid": int(fields[1]), "ticks": int(fields[11]) + int(fields[12]),
                        "start_ticks": int(fields[19]),
                        "rss_mb": int(fields[21]) * os.sysconf("SC_PAGE_SIZE") / 1048576,
                    })
                except (FileNotFoundError, ProcessLookupError):
                    pass
                except (PermissionError, ValueError, IndexError):
                    denied += 1
        except (FileNotFoundError, ProcessLookupError):
            pass
        except PermissionError:
            denied += 1
    return rows, denied
