"""SQLite access.

One connection per request via a context manager. WAL mode is enabled once
at startup so GET /count and GET /admin/registrations reads never block
behind the rare POST /register write. All queries are parameterized ("?"
placeholders) - never string-built SQL.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import SETTINGS


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SETTINGS.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema() -> None:
    """Create the database file, directory and table if they don't exist yet."""
    db_dir = Path(SETTINGS.db_path).resolve().parent
    db_dir.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                email_normalized TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )


def count_registrations() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM registrations").fetchone()
        return int(row["c"])


def insert_registration(name: str, email: str) -> None:
    """Insert a registration. A duplicate email is silently ignored - the
    UNIQUE constraint is the real dedupe guarantee (race-safe), the caller
    decides what response to send either way."""
    email_normalized = email.strip().lower()
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO registrations (name, email, email_normalized, created_at) "
                "VALUES (?, ?, ?, ?)",
                (name.strip(), email.strip(), email_normalized, created_at),
            )
        except sqlite3.IntegrityError:
            pass


def list_registrations() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT name, email, created_at FROM registrations ORDER BY created_at DESC"
        ).fetchall()
