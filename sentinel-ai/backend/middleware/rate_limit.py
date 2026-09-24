"""
backend/middleware/rate_limit.py
================================
Per-route rate limiting using SlowAPI (AIOHTTP-compatible).

Limits:
  - Read-only endpoints: 120 req / minute
  - Mutating / response endpoints: 10 req / minute
  - Auth endpoints: 20 req / minute (brute-force protection)
"""
from __future__ import annotations

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi import FastAPI

# Shared limiter instance — imported by individual routes as needed
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


def configure_rate_limiter(app: FastAPI) -> None:
    """Attach the rate limiter and its exception handler to the FastAPI app."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
