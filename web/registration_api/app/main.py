"""FastAPI app entrypoint.

Run locally with: uvicorn app.main:app --reload --port 8001
Run in production with: uvicorn app.main:app --host 127.0.0.1 --port 8001 --workers 1
(--workers 1 is required - see security.RateLimiter's docstring.)
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db
from .config import SETTINGS
from .routes import admin, public


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_schema()
    yield


app = FastAPI(title="AETHRA-SEC registration API", docs_url="/docs", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=SETTINGS.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

app.include_router(public.router)
app.include_router(admin.router)
