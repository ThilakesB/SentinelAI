"""
backend/routers/settings.py
=============================
Settings API domain.

GET  /api/settings   Read all settings
POST /api/settings   Partial update (admin only)
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from slowapi.util import get_remote_address

from backend.dependencies import AdminUser, AuthUser, DBSession
from backend.middleware.rate_limit import limiter
from backend.schemas.settings import SettingsResponse, SettingsUpdateRequest

router = APIRouter()


@router.get("", response_model=SettingsResponse, summary="Get all settings")
async def get_settings_api(current_user: AuthUser, db: DBSession) -> SettingsResponse:
    from sqlalchemy import text
    result = await db.execute(text("SELECT key, value_json FROM settings"))
    rows = {row.key: row.value_json for row in result}

    def _val(key: str, default):
        raw = rows.get(key, default)
        try:
            return type(default)(raw) if not isinstance(raw, type(default)) else raw
        except (TypeError, ValueError):
            return default

    return SettingsResponse(
        monitoring_interval_sec=_val("monitoring_interval_sec", 5),
        cpu_anomaly_threshold=_val("cpu_anomaly_threshold", 85.0),
        ram_anomaly_threshold=_val("ram_anomaly_threshold", 80.0),
        auto_kill_critical=_val("auto_kill_critical", False),
        auto_block_ip_critical=_val("auto_block_ip_critical", True),
        abuseipdb_score_threshold=_val("abuseipdb_score_threshold", 75),
        threat_intel_refresh_hours=_val("threat_intel_refresh_hours", 6),
        ml_anomaly_suspicious_threshold=_val("ml_anomaly_suspicious_threshold", -0.1),
        ml_anomaly_critical_threshold=_val("ml_anomaly_critical_threshold", -0.3),
        ml_retrain_hour=_val("ml_retrain_hour", 3),
    )


@router.post("", summary="Update settings (admin only)")
@limiter.limit("10/minute")
async def update_settings(
    request: Request,
    body: SettingsUpdateRequest,
    current_user: AdminUser,
    db: DBSession,
) -> dict:
    from sqlalchemy import text
    updates = body.model_dump(exclude_none=True)
    if not updates:
        return {"updated": 0}

    for key, value in updates.items():
        import orjson
        await db.execute(
            text("UPDATE settings SET value_json = :v, updated_at = NOW(), updated_by = :u WHERE key = :k"),
            {"v": orjson.dumps(value).decode(), "u": str(current_user.id), "k": key},
        )

    return {"updated": len(updates), "keys": list(updates.keys())}
