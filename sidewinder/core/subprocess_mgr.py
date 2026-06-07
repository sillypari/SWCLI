"""Sidewinder Subprocess Manager.

Robust asyncio subprocess management with process group isolation,
real-time streaming, and zombie prevention.

Key design decisions from Wcrack post-mortem:
  - start_new_session=True → process group isolation (no zombies)
  - SIGTERM → 0.5s → SIGKILL (graceful shutdown)
  - Dual stream reader (stdout + stderr) prevents pipe deadlocks
  - AsyncIterator streaming for real-time output (airodump-ng)
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from dataclasses import dataclass
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProcessResult:
    """Result of a completed subprocess."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Return True if the process exited with return code 0."""
        return self.returncode == 0


class SubprocessManager:
    """Manages async subprocesses with process group isolation and cleanup.

    All launched processes are tracked internally so that cleanup_all()
    can terminate every outstanding child on shutdown.  Each process is
    started with start_new_session=True, placing it in its own process
    group so that kill signals reach the entire process tree rather than
    only the direct child.
    """

    def __init__(self) -> None:
        """Initialise with an empty active-process list."""
        self._active_procs: list[asyncio.subprocess.Process] = []

    async def run(
        self,
        cmd: list[str],
        timeout: float = 30.0,
        check: bool = True,
        env: Optional[dict] = None,
    ) -> ProcessResult:
        """Run a command and return its result.

        Args:
            cmd:     Command + args as a list (no shell expansion).
            timeout: Maximum seconds to wait before raising TimeoutError.
            check:   If True, raise RuntimeError on a non-zero exit code.
            env:     Optional mapping of environment variables for the child.

        Returns:
            A ProcessResult containing returncode, stdout, and stderr.

        Raises:
            TimeoutError:   If the command does not finish within *timeout* seconds.
            RuntimeError:   If the command exits non-zero and *check* is True.
        """
        logger.debug("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,   # Critical: process group isolation
            env=env,
        )
        self._active_procs.append(proc)
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            await self._kill_proc(proc)
            raise TimeoutError(
                f"Command timed out after {timeout}s: {' '.join(cmd)}"
            )
        finally:
            if proc in self._active_procs:
                self._active_procs.remove(proc)

        stdout = stdout_b.decode(errors="replace").strip()
        stderr = stderr_b.decode(errors="replace").strip()
        result = ProcessResult(proc.returncode if proc.returncode is not None else -1, stdout, stderr)

        if check and not result.success:
            logger.error(
                "Command failed (rc=%d): %s\nstderr: %s",
                result.returncode,
                " ".join(cmd),
                stderr,
            )
            raise RuntimeError(
                f"Command failed (exit {result.returncode}): {' '.join(cmd)}\n{stderr}"
            )
        return result

    async def stream(
        self,
        cmd: list[str],
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
    ) -> AsyncIterator[str]:
        """Stream stdout line-by-line from a long-running command.

        The process is killed automatically when the iterator is exhausted
        or if the caller breaks out of the loop early (via the finally block).

        Args:
            cmd:     Command + args as a list.
            timeout: Reserved for future use (not currently enforced per-line).
            env:     Optional environment variables for the child process.

        Yields:
            Decoded, right-stripped lines from the child's stdout.

        Example::

            async for line in mgr.stream(["airodump-ng", "wlan1mon"]):
                process(line)
        """
        logger.debug("Streaming: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
        self._active_procs.append(proc)
        try:
            assert proc.stdout is not None
            async for line_b in proc.stdout:
                yield line_b.decode(errors="replace").rstrip()
        finally:
            if proc in self._active_procs:
                self._active_procs.remove(proc)
            await self._kill_proc(proc)
            await proc.wait()

    async def start_background(
        self,
        cmd: list[str],
        env: Optional[dict] = None,
    ) -> asyncio.subprocess.Process:
        """Start a process in the background.

        The caller is responsible for eventually calling kill_background()
        or cleanup_all() to avoid zombie processes.

        Args:
            cmd: Command + args as a list.
            env: Optional environment variables for the child process.

        Returns:
            The asyncio.subprocess.Process object for later control.
        """
        logger.debug("Starting background: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
        self._active_procs.append(proc)
        return proc

    async def kill_background(
        self,
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Kill a background process started with start_background().

        Removes the process from the internal tracking list, sends
        SIGTERM→SIGKILL, and waits for the process to exit.

        Args:
            proc: The process returned by start_background().
        """
        if proc in self._active_procs:
            self._active_procs.remove(proc)
        await self._kill_proc(proc)
        await proc.wait()

    async def cleanup_all(self) -> None:
        """Kill all tracked active processes. Call on shutdown.

        Iterates a snapshot of the active-process list so that removal
        during iteration is safe.  Each process is given up to 2 seconds
        to exit after receiving the kill signal before we move on.
        """
        procs = list(self._active_procs)
        self._active_procs.clear()
        for proc in procs:
            await self._kill_proc(proc)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                logger.warning(
                    "Process pid=%d did not exit within 2 s after kill.",
                    proc.pid,
                )

    @staticmethod
    async def _kill_proc(proc: asyncio.subprocess.Process) -> None:
        """Kill a process group: SIGTERM → 500 ms → SIGKILL.

        Targets the entire process group (via os.killpg) so that child
        processes spawned by *proc* are also cleaned up.

        Args:
            proc: The process to terminate.
        """
        if proc.returncode is not None:
            return  # Already exited — nothing to do
        try:
            if hasattr(os, "getpgid") and hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                await asyncio.sleep(0.5)
                if proc.returncode is None:
                    os.killpg(pgid, signal.SIGKILL)
            else:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.returncode is None:
                    proc.kill()
        except ProcessLookupError:
            pass  # Process already gone
        except OSError as exc:
            logger.debug("Kill error (pid=%d): %s", proc.pid, exc)



# ---------------------------------------------------------------------------
# Module-level singleton convenience API
# ---------------------------------------------------------------------------

_manager: Optional[SubprocessManager] = None


def get_manager() -> SubprocessManager:
    """Return the module-level SubprocessManager singleton.

    Creates the singleton on first call (lazy initialisation).
    """
    global _manager
    if _manager is None:
        _manager = SubprocessManager()
    return _manager


async def run(
    cmd: list[str],
    timeout: float = 30.0,
    check: bool = True,
    env: Optional[dict] = None,
) -> ProcessResult:
    """Convenience wrapper around SubprocessManager.run().

    Uses the module-level singleton manager.  See SubprocessManager.run()
    for full parameter documentation.
    """
    return await get_manager().run(cmd, timeout=timeout, check=check, env=env)


async def stream(
    cmd: list[str],
    timeout: Optional[float] = None,
    env: Optional[dict] = None,
) -> AsyncIterator[str]:
    """Convenience wrapper around SubprocessManager.stream().

    Uses the module-level singleton manager.  See SubprocessManager.stream()
    for full parameter documentation.
    """
    async for line in get_manager().stream(cmd, timeout=timeout, env=env):
        yield line
