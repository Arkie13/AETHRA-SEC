"""Admin auth and abuse mitigation."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict

from fastapi import Header, HTTPException, Request

from .config import SETTINGS


def verify_admin_token(authorization: str = Header(default="")) -> None:
    """FastAPI dependency: raise 401 unless a valid bearer token is given.

    Compared with hmac.compare_digest, mirroring the constant-time discipline
    aethra_sec/security/password.py uses for its own credential comparisons.
    """
    expected = SETTINGS.admin_token
    if not expected:
        # An unset secret must never mean "open" - refuse everything rather
        # than silently granting access because nothing was configured.
        raise HTTPException(status_code=401, detail="Admin access is not configured.")
    prefix = "Bearer "
    provided = authorization[len(prefix):] if authorization.startswith(prefix) else ""
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing admin token.")


class RateLimiter:
    """In-process per-key sliding window.

    Only correct with a single uvicorn worker (see deploy/README) - each
    worker process would otherwise keep its own counters, silently widening
    the effective limit.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        """Record one hit for `key`; return False once the limit is exceeded."""
        now = time.monotonic()
        window_start = now - self._window_seconds
        hits = self._hits[key]
        while hits and hits[0] < window_start:
            hits.pop(0)
        if len(hits) >= self._max_requests:
            return False
        hits.append(now)
        return True


def client_ip(request: Request) -> str:
    """The real client IP behind Caddy's reverse proxy.

    Falls back to the raw connection address for local testing, where
    there is no proxy setting X-Forwarded-For.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
