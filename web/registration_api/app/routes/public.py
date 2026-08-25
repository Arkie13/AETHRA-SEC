"""Public endpoints: registration and the aggregate count.

No accounts, no passwords, no login here - this is anonymous early-access
interest capture only (see the plan's explicit V1 scope).
"""

from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request

from .. import db
from ..config import SETTINGS
from ..models import CountResponse, RegisterRequest, RegisterResponse
from ..security import RateLimiter, client_ip

router = APIRouter()

_register_limiter = RateLimiter(max_requests=SETTINGS.rate_limit_per_10min, window_seconds=600)
_count_limiter = RateLimiter(max_requests=60, window_seconds=60)


@router.get("/count", response_model=CountResponse)
def get_count(request: Request) -> CountResponse:
    if not _count_limiter.check(client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests.")
    return CountResponse(count=db.count_registrations())


@router.post("/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, request: Request) -> RegisterResponse:
    if not _register_limiter.check(client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    # Bot deterrence: a filled honeypot or an implausibly fast submission
    # gets a normal-looking 200 with no insert - never an error, which
    # would hand an attacker a signal to tune around.
    is_bot = bool(payload.company.strip())
    if not is_bot and payload.loaded_at_ms:
        elapsed_seconds = (time.time() * 1000 - payload.loaded_at_ms) / 1000
        if elapsed_seconds < SETTINGS.min_seconds_since_load:
            is_bot = True

    if not is_bot:
        # Duplicate emails are silently absorbed by the UNIQUE constraint in
        # db.insert_registration - never surfaced as an error, so a stranger
        # can't use this endpoint to learn which emails are on the list.
        db.insert_registration(payload.name, payload.email)

    return RegisterResponse(count=db.count_registrations())
