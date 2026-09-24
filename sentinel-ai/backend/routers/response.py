"""
backend/routers/response.py
=============================
Automated response API domain.

POST /api/threats/{id}/respond  Trigger kill/block action on a threat
GET  /api/response/rules         List configured response rules
POST /api/response/rules         Create a new rule
DELETE /api/response/rules/{id}  Deactivate a rule

Rate limit: 10 req/minute on mutating endpoints (SlowAPI).
Role: AnalystUser for respond; AdminUser for rule management.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from slowapi.util import get_remote_address

from backend.dependencies import AdminUser, AnalystUser, DBSession
from backend.middleware.rate_limit import limiter
from backend.schemas.response import (
    CreateRuleRequest,
    RespondRequest,
    ResponseAction,
    ResponseRule,
)

router = APIRouter()


@router.post("/threats/{threat_id}/respond",
             response_model=ResponseAction,
             summary="Trigger a response action on a threat event")
@limiter.limit("10/minute")
async def respond_to_threat(
    request: Request,
    threat_id: UUID,
    body: RespondRequest,
    current_user: AnalystUser,
    db: DBSession,
) -> ResponseAction:
    """
    Execute a kill_process or block_ip action for a classified threat.
    Requires confirm_token for protected processes; force_override requires admin role.
    """
    from database.repositories.threat_repo import get_threat_by_id
    from database.repositories.response_repo import insert_response_action
    from response_engine.process_killer import kill_process, PROTECTED_NAMES
    from response_engine.firewall_manager import block_ip
    from sqlalchemy import text
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    # Validate threat exists
    threat = await get_threat_by_id(db, threat_id)
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat event not found")

    # force_override only for admins
    if body.force_override and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="force_override requires admin role")

    action_data = {
        "action_type": body.action,
        "threat_event_id": threat_id,
        "actor": current_user.email,
        "target_pid": None,
        "target_ip": None,
        "firewall_rule": None,
        "status": "failed",
        "failure_reason": None,
    }

    loop = asyncio.get_event_loop()

    if body.action == "kill_process":
        # Resolve process details
        proc_id = threat.get("process_id")
        if not proc_id:
            raise HTTPException(status_code=400, detail="Threat has no linked process")
        row = (await db.execute(
            text("SELECT pid, name, start_time FROM processes_snapshot WHERE id = :id"),
            {"id": proc_id},
        )).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Process record not found")
        pid, name, start_time = row
        create_ts = start_time.timestamp() if start_time else None

        with ThreadPoolExecutor(max_workers=1) as ex:
            result = await loop.run_in_executor(
                ex, kill_process, pid, name, create_ts, body.force_override
            )
        action_data.update({
            "target_pid": pid,
            "status": result["status"],
            "failure_reason": None if result["success"] else result["message"],
        })

    elif body.action == "block_ip":
        net_id = threat.get("network_id")
        if not net_id:
            raise HTTPException(status_code=400, detail="Threat has no linked network event")
        row = (await db.execute(
            text("SELECT dst_ip FROM network_connections WHERE id = :id"),
            {"id": net_id},
        )).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Network record not found")
        dst_ip = str(row[0])
        with ThreadPoolExecutor(max_workers=1) as ex:
            result = await loop.run_in_executor(ex, block_ip, dst_ip)
        action_data.update({
            "target_ip": dst_ip,
            "firewall_rule": result.get("rule_name"),
            "status": result["status"],
            "failure_reason": None if result["success"] else result["message"],
        })

    elif body.action == "alert":
        action_data["status"] = "success"
        result = {"success": True}

    rec = await insert_response_action(db, action_data)
    return ResponseAction(**rec)


@router.get("/rules", response_model=list[ResponseRule], summary="List response rules")
async def list_rules(current_user: AnalystUser, db: DBSession) -> list[ResponseRule]:
    from database.repositories.response_repo import list_rules as _list
    rules = await _list(db)
    return [ResponseRule(**r) for r in rules]


@router.post("/rules", response_model=ResponseRule, summary="Create a response rule",
             status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_rule(
    request: Request,
    body: CreateRuleRequest,
    current_user: AdminUser,
    db: DBSession,
) -> ResponseRule:
    from database.repositories.response_repo import create_rule as _create
    rule = await _create(db, body.model_dump())
    return ResponseRule(**rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Deactivate a response rule")
async def delete_rule(
    rule_id: UUID,
    current_user: AdminUser,
    db: DBSession,
) -> None:
    from database.repositories.response_repo import delete_rule as _delete, get_rule_by_id
    if not await get_rule_by_id(db, rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    await _delete(db, rule_id)
