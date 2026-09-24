"""
response_engine/rule_evaluator.py
===================================
Evaluates configured response rules against each classified threat event
and dispatches automated actions when auto_execute=True.

Called as an asyncio background task after each threat is classified.
Never blocks the monitoring cycle — all DB and action I/O is async.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


async def evaluate_and_respond(threat_event: dict) -> None:
    """
    Main entry point. Called per threat event.
    Loads active auto-response rules for the threat level and executes them.
    """
    threat_level = threat_event.get("threat_level")
    threat_id = threat_event.get("id")

    if threat_level == "Normal":
        return  # No response needed for normal events

    try:
        from database.connection import get_db_session
        from database.repositories.response_repo import (
            get_active_rules_for_level,
            insert_response_action,
        )

        async with get_db_session() as db:
            rules = await get_active_rules_for_level(db, threat_level)

        for rule in rules:
            if not rule.get("auto_execute"):
                continue
            await _execute_rule(rule, threat_event)

    except Exception as exc:
        logger.error("rule_evaluation_failed", threat_id=str(threat_id), error=str(exc))


async def _execute_rule(rule: dict, threat_event: dict) -> None:
    """Execute a single auto-response rule against a threat event."""
    action = rule.get("action")
    threat_id = threat_event.get("id")
    actor = "auto"

    from database.connection import get_db_session
    from database.repositories.response_repo import insert_response_action

    result: dict
    target_pid: int | None = None
    target_ip: str | None = None
    rule_name: str | None = None

    try:
        if action == "kill_process":
            result, target_pid = await _do_kill(threat_event, rule)
        elif action == "block_ip":
            result, target_ip, rule_name = await _do_block_ip(threat_event)
        elif action == "alert":
            result = {"success": True, "status": "success", "message": "Alert generated"}
        else:
            return

        async with get_db_session() as db:
            await insert_response_action(db, {
                "action_type": action,
                "threat_event_id": threat_id,
                "target_pid": target_pid,
                "target_ip": target_ip,
                "firewall_rule": rule_name,
                "actor": actor,
                "status": result.get("status", "failed"),
                "failure_reason": None if result.get("success") else result.get("message"),
            })

    except Exception as exc:
        logger.error("rule_execution_failed", action=action, error=str(exc))


async def _do_kill(threat_event: dict, rule: dict) -> tuple[dict, int | None]:
    """Attempt to kill the process linked to this threat event."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from response_engine.process_killer import kill_process

    # Resolve process details from threat event
    process_id = threat_event.get("process_id")
    if not process_id:
        return {"success": False, "status": "failed", "message": "No linked process"}, None

    from database.connection import get_db_session
    from database.repositories.process_repo import get_process_by_pid
    from sqlalchemy import text

    async with get_db_session() as db:
        result = await db.execute(
            text("SELECT pid, name, start_time FROM processes_snapshot WHERE id = :id"),
            {"id": process_id},
        )
        row = result.fetchone()

    if not row:
        return {"success": False, "status": "failed", "message": "Process record not found"}, None

    pid, name, start_time = row
    create_ts = start_time.timestamp() if start_time else None

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        kill_result = await loop.run_in_executor(
            ex,
            kill_process,
            pid,
            name,
            create_ts,
            rule.get("protected_override", False),
        )

    return kill_result, pid


async def _do_block_ip(threat_event: dict) -> tuple[dict, str | None, str | None]:
    """Attempt to block the suspicious IP linked to this threat event."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from response_engine.firewall_manager import block_ip

    network_id = threat_event.get("network_id")
    if not network_id:
        return {"success": False, "status": "failed", "message": "No linked network event"}, None, None

    from database.connection import get_db_session
    from sqlalchemy import text

    async with get_db_session() as db:
        result = await db.execute(
            text("SELECT dst_ip FROM network_connections WHERE id = :id"),
            {"id": network_id},
        )
        row = result.fetchone()

    if not row or not row[0]:
        return {"success": False, "status": "failed", "message": "No dst_ip in network record"}, None, None

    dst_ip = str(row[0])
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        fw_result = await loop.run_in_executor(ex, block_ip, dst_ip)

    return fw_result, dst_ip, fw_result.get("rule_name")
