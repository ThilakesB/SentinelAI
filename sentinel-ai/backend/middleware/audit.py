"""
backend/middleware/audit.py
===========================
Starlette middleware that logs every inbound request and its outcome
to the audit_log table (async, non-blocking).

Captured fields:
  - actor   (from JWT claim or "anonymous")
  - action  (METHOD /path)
  - payload (request body for mutating methods, truncated)
  - ip_address
  - outcome (success / failed / denied)
"""
from __future__ import annotations

import time
from typing import Any

import orjson
import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from backend.auth.service import decode_jwt

logger = structlog.get_logger(__name__)

# Paths excluded from audit (health, docs, static)
_EXCLUDED_PATHS = frozenset(["/health", "/docs", "/redoc", "/openapi.json"])
_MAX_BODY_BYTES = 4096  # Truncate large payloads in the audit log


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _EXCLUDED_PATHS:
            return await call_next(request)

        start = time.monotonic()

        # -- Resolve actor from JWT (best-effort; might fail pre-auth)
        actor = "anonymous"
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            payload = decode_jwt(auth_header[7:])
            if payload:
                actor = payload.get("email", "unknown")

        # -- Capture request body for mutating methods
        body_preview: str | None = None
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                raw = await request.body()
                body_preview = raw[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
            except Exception:
                body_preview = "<unreadable>"

        # -- Execute request
        response = await call_next(request)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        outcome = (
            "success" if response.status_code < 400
            else "denied" if response.status_code == 403
            else "failed"
        )

        logger.info(
            "request_audit",
            actor=actor,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            outcome=outcome,
            client_ip=request.client.host if request.client else None,
        )

        # -- Async fire-and-forget DB write (non-blocking)
        _schedule_audit_write(
            actor=actor,
            action=f"{request.method} {request.url.path}",
            resource=request.url.path,
            payload=body_preview,
            ip_address=request.client.host if request.client else None,
            outcome=outcome,
        )

        return response


def _schedule_audit_write(**kwargs: Any) -> None:
    """
    Schedule audit log DB write via asyncio without blocking the response.
    Import is deferred to avoid circular imports at module load time.
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_write_audit(**kwargs))
    except RuntimeError:
        pass  # No event loop — skip audit write (e.g., test context)


async def _write_audit(**kwargs: Any) -> None:
    try:
        from database.repositories.log_repo import write_audit_log
        await write_audit_log(**kwargs)
    except Exception as exc:
        logger.warning("audit_write_failed", error=str(exc))
