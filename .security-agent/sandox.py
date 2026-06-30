"""
sandbox.py — Docker-based execution sandbox for AI-generated exploit scripts.

Every script Claude generates passes through:
  1. Static policy check  (fast, blocks obvious bad patterns)
  2. Docker container     (resource limits + capability drop)
  3. Network isolation    (custom bridge → test deployment only)
  4. seccomp profile      (syscall allowlist)

Requirements:
  pip install docker
  docker pull python:3.12-slim
  docker build -t security-agent-sandbox:latest -f Dockerfile.sandbox .
  docker network create --driver bridge --internal \\
      --subnet 172.28.0.0/16 security-agent-testnet
"""

import re
import os
import time
import tempfile
from pathlib import Path
from typing import Literal

try:
    import docker
    _docker_available = True
except ImportError:
    _docker_available = False

SANDBOX_IMAGE = "security-agent-sandbox:latest"
SANDBOX_NETWORK = "security-agent-testnet"
MAX_SCRIPT_BYTES = 8_000
MAX_OUTPUT_BYTES = 50_000

# Syscall allowlist profile path (place alongside this file)
SECCOMP_PROFILE = Path(__file__).parent / "sandbox-seccomp.json"

# Patterns that are blocked before the container even starts
_BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"/etc/(passwd|shadow|hosts|crontab)", "sensitive file access"),
    (r"subprocess.*shell\s*=\s*True", "shell=True subprocess"),
    (r"\bos\.system\b", "os.system call"),
    (r"\beval\s*\(", "eval() call"),
    (r"\bexec\s*\(", "exec() call"),
    (r"import\s+(socket|ftplib|smtplib|imaplib|pty)\b", "blocked stdlib module"),
    (r"(DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;)", "destructive SQL"),
    (r"rm\s+-rf", "destructive shell command"),
    (r">\s*/dev/(sd|vd|nvme)", "raw device write"),
]


def execute_in_sandbox(
    script: str,
    language: Literal["python3", "bash"] = "python3",
    timeout_seconds: int = 30,
    target_host: str = "localhost",
    target_port: int = 8080,
) -> dict:
    """
    Run an AI-generated script in an isolated Docker container.

    Returns:
        {
            "stdout": str,
            "stderr": str,
            "exit_code": int,
            "wall_time_ms": int,
            "blocked": bool,
            "block_reason": str | None,
        }
    """
    # ── 1. STATIC CHECK ───────────────────────────────────────────────
    violations = _static_check(script)
    if violations:
        return {
            "stdout": "",
            "stderr": f"BLOCKED BY SANDBOX POLICY: {'; '.join(violations)}",
            "exit_code": 126,
            "wall_time_ms": 0,
            "blocked": True,
            "block_reason": "; ".join(violations),
        }

    if len(script.encode()) > MAX_SCRIPT_BYTES:
        return {
            "stdout": "",
            "stderr": f"BLOCKED: Script exceeds {MAX_SCRIPT_BYTES} byte limit",
            "exit_code": 126,
            "wall_time_ms": 0,
            "blocked": True,
            "block_reason": "script too large",
        }

    # ── 2. DOCKER EXECUTION ───────────────────────────────────────────
    if not _docker_available:
        return _fallback_subprocess(script, language, timeout_seconds)

    client = docker.from_env()
    ext = "py" if language == "python3" else "sh"
    cmd = ["python3", f"/sandbox/exploit.{ext}"] if language == "python3" \
          else ["bash", f"/sandbox/exploit.{ext}"]

    security_opts = ["no-new-privileges:true"]
    if SECCOMP_PROFILE.exists():
        security_opts.append(f"seccomp={SECCOMP_PROFILE}")

    with tempfile.TemporaryDirectory() as tmpdir:
        script_file = Path(tmpdir) / f"exploit.{ext}"
        script_file.write_text(script)
        script_file.chmod(0o500)

        start = time.monotonic()
        try:
            logs = client.containers.run(
                image=SANDBOX_IMAGE,
                command=cmd,
                volumes={tmpdir: {"bind": "/sandbox", "mode": "ro"}},
                environment={
                    "TARGET_HOST": target_host,
                    "TARGET_PORT": str(target_port),
                    "TARGET_URL": f"http://{target_host}:{target_port}",
                },
                network=SANDBOX_NETWORK,
                mem_limit="128m",
                memswap_limit="128m",
                cpu_quota=50_000,   # 50% of one CPU core
                pids_limit=32,
                read_only=True,
                tmpfs={"/tmp": "size=10m,mode=1777"},
                cap_drop=["ALL"],
                security_opt=security_opts,
                user="1000:1000",
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
                timeout=timeout_seconds,
            )
            wall_ms = int((time.monotonic() - start) * 1000)
            output = logs if isinstance(logs, bytes) else b""
            return {
                "stdout": output.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES],
                "stderr": "",
                "exit_code": 0,
                "wall_time_ms": wall_ms,
                "blocked": False,
                "block_reason": None,
            }

        except docker.errors.ContainerError as e:
            wall_ms = int((time.monotonic() - start) * 1000)
            stderr_text = ""
            if e.stderr:
                stderr_text = e.stderr.decode("utf-8", errors="replace")[:10_000]
            return {
                "stdout": stderr_text,
                "stderr": str(e)[:2000],
                "exit_code": e.exit_status,
                "wall_time_ms": wall_ms,
                "blocked": False,
                "block_reason": None,
            }

        except Exception as e:
            return {
                "stdout": "",
                "stderr": f"Sandbox error: {e}",
                "exit_code": 127,
                "wall_time_ms": 0,
                "blocked": False,
                "block_reason": None,
            }


def _static_check(script: str) -> list[str]:
    """Pre-flight policy check. Returns list of violation labels."""
    violations = []
    for pattern, label in _BLOCKED_PATTERNS:
        if re.search(pattern, script, re.IGNORECASE):
            violations.append(label)
    return violations


def _fallback_subprocess(script: str, language: str, timeout: int) -> dict:
    """
    Fallback when Docker is unavailable (e.g., local dev without Docker).
    Runs the script in a subprocess with NO sandboxing — for development only.
    """
    import subprocess
    import sys

    print("[SANDBOX WARNING] Docker unavailable — running WITHOUT isolation. "
          "Use only against localhost test deployments.")

    with tempfile.TemporaryDirectory() as tmpdir:
        ext = "py" if language == "python3" else "sh"
        script_file = Path(tmpdir) / f"exploit.{ext}"
        script_file.write_text(script)

        interp = sys.executable if language == "python3" else "bash"
        start = time.monotonic()
        try:
            result = subprocess.run(
                [interp, str(script_file)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "stdout": result.stdout[:MAX_OUTPUT_BYTES],
                "stderr": result.stderr[:10_000],
                "exit_code": result.returncode,
                "wall_time_ms": int((time.monotonic() - start) * 1000),
                "blocked": False,
                "block_reason": None,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "Script timed out",
                "exit_code": 124,
                "wall_time_ms": timeout * 1000,
                "blocked": False,
                "block_reason": None,
            }