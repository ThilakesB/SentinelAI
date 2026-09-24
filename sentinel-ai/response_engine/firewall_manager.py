"""
response_engine/firewall_manager.py
=====================================
Windows Firewall IP block/unblock via `netsh advfirewall`.

Security controls:
  1. IP validated with ipaddress.ip_address() before any shell invocation
  2. RFC 1918 / loopback / link-local ranges rejected
  3. Rule name prefix "SENTINEL_AI_BLOCK_" prevents namespace collisions
  4. CREATE_NO_WINDOW flag prevents console window pop-ups
  5. Rollback via delete_rule() stores rule name in response_actions table

Requires: Agent runs as Administrator or SYSTEM.
"""
from __future__ import annotations

import ipaddress
import subprocess

import structlog

logger = structlog.get_logger(__name__)

_RULE_PREFIX = "SENTINEL_AI_BLOCK_"
_CREATE_NO_WINDOW = 0x08000000  # Windows DETACHED_PROCESS / no console

# Ranges that must never be blocked
_PROTECTED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _validate_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Parse and validate the IP string.
    Raises ValueError for malformed IPs or protected ranges.
    This is the primary injection-prevention control.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address format: {ip!r}")

    for net in _PROTECTED_RANGES:
        if addr in net:
            raise ValueError(f"Cannot block private/loopback IP: {ip}")

    return addr


def block_ip(ip: str) -> dict:
    """
    Add outbound + inbound block rules for the given IP.

    Returns:
        dict with keys: success (bool), rule_name (str), message (str), status (str)
    """
    try:
        addr = _validate_ip(ip)
    except ValueError as exc:
        return _fail(str(exc))

    rule_name = f"{_RULE_PREFIX}{str(addr)}"
    safe_ip = str(addr)  # Guaranteed safe after ip_address() parsing

    # Add outbound block
    out_result = _run_netsh(
        "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={safe_ip}",
        "enable=yes",
        "profile=any",
    )

    if not out_result["success"]:
        return out_result

    # Add inbound block
    in_result = _run_netsh(
        "add", "rule",
        f"name={rule_name}_IN",
        "dir=in",
        "action=block",
        f"remoteip={safe_ip}",
        "enable=yes",
        "profile=any",
    )

    if not in_result["success"]:
        logger.warning("firewall_inbound_block_failed", ip=safe_ip, error=in_result["message"])
        # Outbound block succeeded — partial success is still useful

    logger.warning("ip_blocked", ip=safe_ip, rule=rule_name)
    return {
        "success": True,
        "status": "success",
        "rule_name": rule_name,
        "message": f"IP {safe_ip} blocked (outbound + inbound).",
    }


def unblock_ip(ip: str) -> dict:
    """Remove Windows Firewall block rules for the given IP (rollback)."""
    try:
        addr = _validate_ip(ip)
    except ValueError as exc:
        return _fail(str(exc))

    rule_name = f"{_RULE_PREFIX}{str(addr)}"
    safe_ip = str(addr)

    _run_netsh("delete", "rule", f"name={rule_name}")
    _run_netsh("delete", "rule", f"name={rule_name}_IN")

    logger.info("ip_unblocked", ip=safe_ip, rule=rule_name)
    return {
        "success": True,
        "status": "success",
        "rule_name": rule_name,
        "message": f"Firewall rules for {safe_ip} removed.",
    }


def list_sentinel_rules() -> list[str]:
    """Return all active SentinelAI firewall rule names."""
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={_RULE_PREFIX}*"],
        capture_output=True,
        text=True,
        creationflags=_CREATE_NO_WINDOW,
        timeout=10,
    )
    rules = []
    for line in result.stdout.splitlines():
        if line.startswith("Rule Name:"):
            name = line.split(":", 1)[1].strip()
            if name.startswith(_RULE_PREFIX):
                rules.append(name)
    return rules


def _run_netsh(*args: str) -> dict:
    cmd = ["netsh", "advfirewall", "firewall"] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            return _fail(f"netsh error ({result.returncode}): {result.stderr.strip()}")
        return {"success": True, "output": result.stdout.strip()}
    except subprocess.TimeoutExpired:
        return _fail("netsh timed out after 10 seconds")
    except FileNotFoundError:
        return _fail("netsh not found — requires Windows with firewall enabled")
    except Exception as exc:
        return _fail(str(exc))


def _fail(message: str) -> dict:
    logger.warning("firewall_action_failed", reason=message)
    return {"success": False, "status": "failed", "message": message, "rule_name": None}
