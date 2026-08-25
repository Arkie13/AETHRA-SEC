"""Environment configuration for the registration API.

Standalone: does not import anything from aethra_sec/. Env vars follow the
same AETHRA_<AREA>_<SETTING> convention as the desktop app's .env, under
their own AETHRA_REG_ prefix so the two services' configuration never
collides if they ever end up loaded in the same shell.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    raw = _env_str(name)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Everything the app needs, read once at startup."""

    db_path: str = field(default_factory=lambda: _env_str("AETHRA_REG_DB_PATH", "./registrations.db"))
    allowed_origins: list[str] = field(default_factory=lambda: _env_list("AETHRA_REG_ALLOWED_ORIGINS"))
    admin_token: str = field(default_factory=lambda: _env_str("AETHRA_REG_ADMIN_TOKEN"))
    rate_limit_per_10min: int = field(default_factory=lambda: _env_int("AETHRA_REG_RATE_LIMIT_PER_10MIN", 5))
    min_seconds_since_load: int = field(default_factory=lambda: _env_int("AETHRA_REG_MIN_SECONDS_SINCE_LOAD", 3))


SETTINGS = Settings()
