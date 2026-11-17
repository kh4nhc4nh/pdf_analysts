from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Sequence

OUTPUT_LIMIT = 16_000
STDERR_LIMIT = 4_000
DEFAULT_CAPTURE_LIMIT = 2 * 1024 * 1024
_ANALYSIS_DEADLINE: ContextVar[float | None] = ContextVar("pdf_analysis_deadline", default=None)


def set_analysis_deadline(seconds: int) -> Token:
    """Set a per-analysis wall-clock deadline for child-process invocations."""
    return _ANALYSIS_DEADLINE.set(time.monotonic() + max(1, seconds))


def reset_analysis_deadline(token: Token) -> None:
    _ANALYSIS_DEADLINE.reset(token)


def _effective_timeout(requested: float) -> float | None:
    deadline = _ANALYSIS_DEADLINE.get()
    if deadline is None:
        return requested
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(float(requested), remaining)


def _bounded_command(argv: Sequence[str], max_bytes: int) -> list[str] | None:
    """Apply an OS file-size limit without subprocess preexec_fn.

    preexec_fn can deadlock in a multithreaded process such as FastAPI's threadpool.
    On the Linux service we use util-linux prlimit, which sets RLIMIT_FSIZE and then
    execs the requested analyzer. If prlimit is missing, fail closed rather than
    silently running an unbounded parser on an untrusted sample.
    """
    command = [str(arg) for arg in argv]
    if os.name == "posix":
        prlimit_path = shutil.which("prlimit")
        if not prlimit_path:
            return None
        return [prlimit_path, f"--fsize={max_bytes}", "--", *command]
    # The production deployment target is Ubuntu/Linux. Keep unit-test/dev portability
    # on other platforms, but the systemd service must be deployed on Linux.
    return command


def _decode_prefix(path, limit: int) -> tuple[str, bool]:
    path.seek(0, os.SEEK_END)
    size = path.tell()
    path.seek(0)
    data = path.read(limit + 1)
    truncated = size > limit or len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def run_tool(
    name: str,
    argv: Sequence[str],
    *,
    timeout: int = 20,
    max_written_file_bytes: int | None = None,
    capture_limit_bytes: int = DEFAULT_CAPTURE_LIMIT,
) -> dict:
    """Run a fixed local analyzer without a shell, with timeout and bounded output capture."""
    cap = max_written_file_bytes or capture_limit_bytes
    effective_timeout = _effective_timeout(timeout)
    if effective_timeout is None:
        return {"name": name, "status": "analysis_deadline_exceeded"}
    try:
        bounded_argv = _bounded_command(argv, cap)
        if bounded_argv is None:
            return {"name": name, "status": "missing_resource_limiter", "required_tool": "prlimit"}
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            proc = subprocess.Popen(
                bounded_argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                close_fds=True,
            )
            try:
                returncode = proc.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                deadline = _ANALYSIS_DEADLINE.get()
                return {
                    "name": name,
                    "status": "timeout",
                    "timeout_seconds": round(effective_timeout, 3),
                    "analysis_deadline_exhausted": deadline is not None and time.monotonic() >= deadline,
                }
            stdout, stdout_truncated = _decode_prefix(stdout_file, OUTPUT_LIMIT)
            stderr, stderr_truncated = _decode_prefix(stderr_file, STDERR_LIMIT)
            return {
                "name": name,
                "status": "completed",
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": stdout_truncated or stderr_truncated,
                "command": [str(x) for x in argv[:3]] + (["...", str(argv[-1])] if len(argv) > 4 else [str(x) for x in argv[3:]]),
            }
    except FileNotFoundError:
        return {"name": name, "status": "missing_tool"}
    except Exception as exc:
        return {"name": name, "status": "execution_error", "error": f"{type(exc).__name__}: {exc}"}


def run_binary_to_path(
    name: str,
    argv: Sequence[str],
    output_path: Path,
    *,
    timeout: int = 15,
    max_bytes: int = 1024 * 1024,
) -> dict:
    """Capture binary stdout directly to a controlled file with an OS size cap."""
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    effective_timeout = _effective_timeout(timeout)
    if effective_timeout is None:
        output_path.unlink(missing_ok=True)
        return {"name": name, "status": "analysis_deadline_exceeded"}
    try:
        bounded_argv = _bounded_command(argv, max_bytes)
        if bounded_argv is None:
            output_path.unlink(missing_ok=True)
            return {"name": name, "status": "missing_resource_limiter", "required_tool": "prlimit"}
        with output_path.open("wb") as output_file, tempfile.TemporaryFile() as stderr_file:
            proc = subprocess.Popen(
                bounded_argv,
                stdin=subprocess.DEVNULL,
                stdout=output_file,
                stderr=stderr_file,
                shell=False,
                close_fds=True,
            )
            try:
                returncode = proc.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                output_path.unlink(missing_ok=True)
                deadline = _ANALYSIS_DEADLINE.get()
                return {
                    "name": name,
                    "status": "timeout",
                    "timeout_seconds": round(effective_timeout, 3),
                    "analysis_deadline_exhausted": deadline is not None and time.monotonic() >= deadline,
                }
            output_file.flush()
            size = output_path.stat().st_size if output_path.exists() else 0
            stderr, stderr_truncated = _decode_prefix(stderr_file, STDERR_LIMIT)
            if size > max_bytes:
                output_path.unlink(missing_ok=True)
                return {"name": name, "status": "output_limit_exceeded", "limit_bytes": max_bytes}
            if returncode not in (0, 3):
                return {
                    "name": name,
                    "status": "completed",
                    "returncode": returncode,
                    "stderr": stderr,
                    "stderr_truncated": stderr_truncated,
                    "output_bytes": size,
                }
            return {
                "name": name,
                "status": "completed",
                "returncode": returncode,
                "stderr": stderr,
                "stderr_truncated": stderr_truncated,
                "output_bytes": size,
            }
    except FileNotFoundError:
        output_path.unlink(missing_ok=True)
        return {"name": name, "status": "missing_tool"}
    except Exception as exc:
        output_path.unlink(missing_ok=True)
        return {"name": name, "status": "execution_error", "error": f"{type(exc).__name__}: {exc}"}


def output_mentions_infection(result: dict) -> bool:
    # ClamAV documents return code 1 for a detection and 2 for an error.
    if result.get("status") != "completed" or result.get("returncode") != 1:
        return False
    text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    return " FOUND" in text or text.rstrip().endswith("FOUND")
