"""Read-only host meters. Process rows remain limited to the selected UID scope."""
from pathlib import Path


def read_system(root="/proc"):
    root = Path(root)
    result = {"cpus": {}, "memory_total": 0, "memory_used": 0,
              "swap_total": 0, "swap_used": 0, "load": "-", "uptime": 0}
    try:
        for line in (root / "stat").read_text().splitlines():
            fields = line.split()
            if fields and (fields[0] == "cpu" or fields[0][3:].isdigit() and fields[0].startswith("cpu")):
                # user/nice already include guest; do not count guest twice.
                values = [int(v) for v in fields[1:9]]
                result["cpus"][fields[0]] = (sum(values), values[3] + values[4])
        mem = {}
        for line in (root / "meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            mem[key] = int(value.split()[0]) * 1024
        result["memory_total"] = mem.get("MemTotal", 0)
        result["memory_used"] = max(0, mem.get("MemTotal", 0) - mem.get("MemAvailable", mem.get("MemFree", 0)))
        result["swap_total"] = mem.get("SwapTotal", 0)
        result["swap_used"] = max(0, mem.get("SwapTotal", 0) - mem.get("SwapFree", 0))
        result["load"] = " ".join((root / "loadavg").read_text().split()[:3])
        result["uptime"] = float((root / "uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        result["unavailable"] = True
    return result


def cpu_percent(current, previous):
    result = {}
    for name, (total, idle) in current.get("cpus", {}).items():
        if name not in previous.get("cpus", {}):
            result[name] = None
            continue
        old_total, old_idle = previous["cpus"][name]
        delta = total - old_total
        result[name] = max(0, min(100, 100 * (delta - (idle - old_idle)) / delta)) if delta > 0 else 0
    return result
