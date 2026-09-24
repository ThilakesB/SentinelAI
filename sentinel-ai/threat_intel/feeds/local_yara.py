"""
threat_intel/feeds/local_yara.py
=================================
YARA rule scanner for local process executables.

Scans EXE files against community YARA rule sets at process discovery time.
Rules are loaded from the configured YARA_RULES_DIR (default: ./rules/).

Recommended community rule repos (git clone into ./rules/):
  - https://github.com/Yara-Rules/rules
  - https://github.com/Neo23x0/signature-base

YARA scanning is synchronous/CPU-bound — runs in thread pool executor.
Requires: yara-python (pip install yara-python)
          YARA C library (installed via setup_windows.ps1)

Returns: list of matching rule names, or empty list if clean.
"""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import structlog

from backend.config import get_settings

logger = structlog.get_logger(__name__)

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="yara_scanner")
_compiled_rules = None  # Cached compiled ruleset
_rules_mtime: float = 0.0  # Last modification time for hot-reload


def _get_rules():
    """Load and cache compiled YARA rules from YARA_RULES_DIR."""
    global _compiled_rules, _rules_mtime

    try:
        import yara
    except ImportError:
        return None

    rules_dir = get_settings().yara_rules_dir
    if not rules_dir.exists():
        logger.warning("yara_rules_dir_missing", path=str(rules_dir))
        return None

    # Collect all .yar / .yara files
    rule_files: dict[str, str] = {}
    for f in rules_dir.rglob("*.yar"):
        rule_files[f.stem] = str(f)
    for f in rules_dir.rglob("*.yara"):
        rule_files[f.stem] = str(f)

    if not rule_files:
        return None

    # Check if any rules have changed since last compile
    latest_mtime = max(Path(p).stat().st_mtime for p in rule_files.values())
    if _compiled_rules is not None and latest_mtime <= _rules_mtime:
        return _compiled_rules

    # Compile ruleset
    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
        _rules_mtime = latest_mtime
        logger.info("yara_rules_compiled", count=len(rule_files))
        return _compiled_rules
    except yara.SyntaxError as exc:
        logger.error("yara_compile_error", error=str(exc))
        return None


def _scan_file_sync(exe_path: str) -> list[str]:
    """
    Synchronous YARA scan. Returns list of matching rule names.
    Runs in thread pool to avoid blocking asyncio event loop.
    """
    rules = _get_rules()
    if rules is None or not exe_path:
        return []

    try:
        matches = rules.match(exe_path, timeout=5)  # 5s timeout per file
        return [m.rule for m in matches]
    except Exception as exc:
        logger.debug("yara_scan_error", exe=exe_path, error=str(exc))
        return []


async def scan_file(exe_path: str) -> list[str]:
    """
    Async wrapper — scans exe_path against loaded YARA rules.
    Returns list of matching rule names (empty = clean).
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _scan_file_sync, exe_path)


async def reload_rules() -> int:
    """Force reload of YARA rules from disk. Returns count of rule files loaded."""
    global _compiled_rules, _rules_mtime
    _compiled_rules = None
    _rules_mtime = 0.0

    loop = asyncio.get_event_loop()
    rules = await loop.run_in_executor(_executor, _get_rules)
    rules_dir = get_settings().yara_rules_dir

    count = sum(1 for _ in rules_dir.rglob("*.yar")) + sum(1 for _ in rules_dir.rglob("*.yara"))
    logger.info("yara_rules_reloaded", file_count=count)
    return count
