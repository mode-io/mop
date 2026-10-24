"""Bounded cleanup for process groups created by this guard."""
import asyncio
import os
import signal


async def terminate_group(proc, privileged=False, grace=1.0):
    async def send(sig):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        except PermissionError:
            if not privileged:
                raise
            helper = await asyncio.create_subprocess_exec(
                "sudo", "-n", "/bin/kill", "-" + signal.Signals(sig).name[3:],
                "--", "-" + str(proc.pid),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(helper.wait(), 2)
    # Also terminate children left in our group after the leader exited.
    await send(signal.SIGTERM)
    deadline = asyncio.get_running_loop().time() + grace
    while asyncio.get_running_loop().time() < deadline:
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            pass
        await asyncio.sleep(.02)
    else:
        await send(signal.SIGKILL)
    await asyncio.wait_for(proc.wait(), grace + 1)
