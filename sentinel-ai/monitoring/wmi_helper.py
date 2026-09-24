"""
monitoring/wmi_helper.py
========================
Thin wrappers around WMI / PowerShell queries for Windows-specific
process data that psutil cannot provide:
  - Code signing status (Authenticode)
  - Full command line
  - Parent process chain

Requires: pywin32, wmi
Privilege: User-level for most queries; Admin for full command-line access.

All functions are synchronous and should be called from a thread pool
executor to avoid blocking the asyncio event loop.
"""
from __future__ import annotations

import subprocess
import threading
from functools import lru_cache
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Thread-local WMI connections (WMI COM objects are not thread-safe)
_wmi_local = threading.local()


def _get_wmi():
    """Return a thread-local WMI connection."""
    if not hasattr(_wmi_local, "conn"):
        try:
            import wmi
            _wmi_local.conn = wmi.WMI()
        except Exception as exc:
            logger.warning("wmi_init_failed", error=str(exc))
            _wmi_local.conn = None
    return _wmi_local.conn


# ── Code Signing ──────────────────────────────────────────────────────────────

def get_authenticode_status(exe_path: str) -> tuple[bool | None, str | None]:
    """
    Returns (is_signed, signer_name) for the given executable path.
    Uses PowerShell Get-AuthenticodeSignature which is always available on Win10+.
    Returns (None, None) if the check fails.
    """
    if not exe_path:
        return None, None
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"$s = Get-AuthenticodeSignature -FilePath '{exe_path}'; "
                "$s.Status.ToString() + '|' + $s.SignerCertificate.Subject",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        if result.returncode != 0 or not result.stdout.strip():
            return False, None

        parts = result.stdout.strip().split("|", 1)
        status = parts[0].strip()
        subject = parts[1].strip() if len(parts) > 1 else None

        is_signed = status == "Valid"
        signer_name = _extract_cn(subject) if is_signed else None
        return is_signed, signer_name

    except Exception as exc:
        logger.debug("authenticode_check_failed", exe=exe_path, error=str(exc))
        return None, None


def _extract_cn(subject: str | None) -> str | None:
    """Extract CN= value from a certificate subject string."""
    if not subject:
        return None
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:]
    return subject


# ── Process Info ──────────────────────────────────────────────────────────────

def get_process_commandline(pid: int) -> str | None:
    """Return the full command line for a PID via WMI."""
    conn = _get_wmi()
    if conn is None:
        return None
    try:
        procs = conn.Win32_Process(ProcessId=pid)
        if procs:
            return procs[0].CommandLine
        return None
    except Exception as exc:
        logger.debug("wmi_cmdline_failed", pid=pid, error=str(exc))
        return None


def get_process_owner(pid: int) -> str | None:
    """Return 'DOMAIN\\user' for the process owner via WMI."""
    conn = _get_wmi()
    if conn is None:
        return None
    try:
        procs = conn.Win32_Process(ProcessId=pid)
        if procs:
            domain, user = procs[0].GetOwner().Domain, procs[0].GetOwner().User
            if user:
                return f"{domain}\\{user}"
        return None
    except Exception as exc:
        logger.debug("wmi_owner_failed", pid=pid, error=str(exc))
        return None


def get_parent_chain(pid: int, depth: int = 5) -> list[dict]:
    """
    Walk the process parent chain up to `depth` levels.
    Returns list of {pid, name} dicts from immediate parent to root.
    """
    conn = _get_wmi()
    if conn is None:
        return []

    chain: list[dict] = []
    current_pid = pid
    seen: set[int] = {pid}

    for _ in range(depth):
        try:
            procs = conn.Win32_Process(ProcessId=current_pid)
            if not procs:
                break
            parent_pid = procs[0].ParentProcessId
            if parent_pid is None or parent_pid in seen or parent_pid == 0:
                break
            parent_procs = conn.Win32_Process(ProcessId=parent_pid)
            if not parent_procs:
                break
            chain.append({"pid": parent_pid, "name": parent_procs[0].Name})
            seen.add(parent_pid)
            current_pid = parent_pid
        except Exception:
            break

    return chain


# ── System Services ───────────────────────────────────────────────────────────

def is_system_service(pid: int) -> bool:
    """Check if a PID corresponds to a Windows system service via WMI."""
    conn = _get_wmi()
    if conn is None:
        return False
    try:
        services = conn.Win32_Service()
        service_pids = {int(s.ProcessId) for s in services if s.ProcessId}
        return pid in service_pids
    except Exception:
        return False
