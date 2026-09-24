"""Pooled MySQL connectivity.

Responsibilities:

* keep a small pool of live connections so the UI never pays connection setup
  cost on a query;
* detect a dropped server and reconnect on the next checkout, publishing a
  ``DATABASE_STATUS_CHANGED`` event when the observed state flips, so the
  dashboard shows ``DATABASE OFFLINE`` truthfully rather than the last good
  value (§57);
* expose only parameterised execution helpers - there is no API here that
  accepts a fully-formed SQL string built from user input (§35, §97).
"""

from __future__ import annotations

import queue
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Iterator, Sequence

from aethra_sec.config.settings import DatabaseSettings
from aethra_sec.core.errors import DatabaseError, DatabaseUnavailableError
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("database.connection")

#: A pooled connection idle at least this long is health-checked before reuse;
#: one used more recently is trusted, so an active application does not pay a
#: ping round-trip per statement. MySQL's default wait_timeout is 28,800s, so
#: 30s is far inside the window where a connection is certainly still alive.
PING_IDLE_SECONDS = 30.0

try:  # pragma: no cover - import availability differs per installation
    import mysql.connector
    from mysql.connector import Error as MySQLError

    MYSQL_AVAILABLE = True
    MYSQL_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover
    mysql = None  # type: ignore[assignment]
    MySQLError = Exception  # type: ignore[assignment,misc]
    MYSQL_AVAILABLE = False
    MYSQL_IMPORT_ERROR = str(exc)


class DatabaseManager:
    """Owns the connection pool and every SQL entry point."""

    def __init__(
        self,
        settings: DatabaseSettings,
        *,
        status_callback: Any = None,
    ) -> None:
        """Create a manager. No connection is opened until first use.

        Args:
            settings: MySQL connection parameters.
            status_callback: optional ``callable(connected: bool, detail: str)``
                invoked when the observed connectivity state changes.
        """
        self._settings = settings
        self._pool: queue.LifoQueue[Any] = queue.LifoQueue(maxsize=settings.pool_size)
        self._lock = threading.RLock()
        self._created = 0
        self._connected: bool | None = None
        self._last_error = ""
        self._last_success: datetime | None = None
        self._status_callback = status_callback
        self._closed = False
        self._query_count = 0

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    @property
    def settings(self) -> DatabaseSettings:
        """The settings this manager was built with."""
        return self._settings

    @property
    def is_connected(self) -> bool:
        """Last observed connectivity state (``False`` before the first probe)."""
        return bool(self._connected)

    @property
    def last_error(self) -> str:
        """Text of the most recent connection or query failure."""
        return self._last_error

    @property
    def last_success(self) -> datetime | None:
        """Timestamp of the last successful statement."""
        return self._last_success

    @property
    def query_count(self) -> int:
        """Number of statements executed through this manager."""
        return self._query_count

    def _set_state(self, connected: bool, detail: str = "") -> None:
        """Record connectivity and notify only on an actual transition."""
        with self._lock:
            changed = self._connected != connected
            self._connected = connected
            if connected:
                self._last_success = utcnow()
                self._last_error = ""
            elif detail:
                self._last_error = detail
        if changed and self._status_callback:
            try:
                self._status_callback(connected, detail)
            except Exception:  # noqa: BLE001 - status reporting must not raise
                LOGGER.exception("Database status callback failed")

    # ------------------------------------------------------------------
    # Pool management
    # ------------------------------------------------------------------
    def _new_connection(self) -> Any:
        """Open one raw connection.

        Raises:
            DatabaseUnavailableError: when the driver is missing or the server
                cannot be reached.
        """
        if not MYSQL_AVAILABLE:
            raise DatabaseUnavailableError(
                f"mysql-connector-python is not installed ({MYSQL_IMPORT_ERROR}). "
                "Install it with: pip install mysql-connector-python",
                user_message=(
                    "The MySQL driver is not installed. Run "
                    "'pip install -r requirements.txt' and restart AETHRA-SEC."
                ),
            )
        settings = self._settings
        try:
            connection = mysql.connector.connect(
                host=settings.host,
                port=settings.port,
                database=settings.database,
                user=settings.user,
                password=settings.password,
                connection_timeout=settings.connect_timeout,
                autocommit=True,
                charset="utf8mb4",
                collation="utf8mb4_unicode_ci",
                use_pure=True,
                time_zone="+00:00",
            )
        except MySQLError as exc:
            detail = str(exc)
            self._set_state(False, detail)
            raise DatabaseUnavailableError(
                f"Could not connect to MySQL at {settings.host}:{settings.port}"
                f"/{settings.database}: {detail}",
                user_message=(
                    "DATABASE OFFLINE - could not connect to MySQL at "
                    f"{settings.host}:{settings.port}. Check that the MySQL "
                    "service is running and that the database credentials in the "
                    "configuration file are "
                    "correct."
                ),
            ) from exc
        with self._lock:
            self._created += 1
        self._set_state(True)
        connection._aethra_checked_at = time.monotonic()  # noqa: SLF001
        return connection

    @contextmanager
    def connection(self) -> Iterator[Any]:
        """Check a healthy connection out of the pool and return it afterwards.

        Raises:
            DatabaseUnavailableError: when no healthy connection can be
                obtained.
        """
        if self._closed:
            raise DatabaseUnavailableError(
                "The database manager has been shut down.",
                user_message="DATABASE OFFLINE - the application is shutting down.",
            )

        conn = None
        try:
            conn = self._pool.get_nowait()
        except queue.Empty:
            conn = None

        # Only ping a connection that has sat idle long enough to have plausibly
        # been dropped by the server. Pinging on every checkout added a network
        # round-trip to every statement - including the ones the UI thread makes
        # for the sidebar badges - which is pure latency on a connection used
        # seconds ago. A freshly used connection is trusted; a failed statement
        # is still caught below and the connection discarded.
        if conn is not None:
            idle = time.monotonic() - getattr(conn, "_aethra_checked_at", 0.0)
            if idle >= PING_IDLE_SECONDS and not self._is_healthy(conn):
                self._discard(conn)
                conn = None

        if conn is None:
            conn = self._new_connection()
        else:
            conn._aethra_checked_at = time.monotonic()  # noqa: SLF001

        try:
            yield conn
        except MySQLError as exc:
            self._set_state(False, str(exc))
            self._discard(conn)
            conn = None
            raise DatabaseError(
                f"Database operation failed: {exc}",
                user_message=(
                    "The database operation could not be completed. See the "
                    "System Health screen for details."
                ),
            ) from exc
        finally:
            if conn is not None:
                self._release(conn)

    def _is_healthy(self, conn: Any) -> bool:
        """Ping a pooled connection, reconnecting once if the server dropped."""
        try:
            conn.ping(reconnect=True, attempts=1, delay=0)
            return True
        except Exception:  # noqa: BLE001 - any failure means "discard it"
            return False

    def _discard(self, conn: Any | None) -> None:
        """Close a connection and forget it."""
        if conn is None:
            return
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        with self._lock:
            self._created = max(0, self._created - 1)

    def _release(self, conn: Any) -> None:
        """Return a connection to the pool, closing it when the pool is full."""
        if self._closed:
            self._discard(conn)
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            self._discard(conn)

    def close(self) -> None:
        """Close every pooled connection (application shutdown)."""
        self._closed = True
        while True:
            try:
                self._discard(self._pool.get_nowait())
            except queue.Empty:
                break
        LOGGER.info("Database connection pool closed.")

    # ------------------------------------------------------------------
    # Query helpers - all parameterised
    # ------------------------------------------------------------------
    def query(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        """Run a SELECT and return rows as dictionaries.

        Args:
            sql: statement containing ``%s`` placeholders only.
            params: bound values.
        """
        with self.connection() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(sql, tuple(params or ()))
                rows = cursor.fetchall()
            finally:
                cursor.close()
        with self._lock:
            self._query_count += 1
        self._set_state(True)
        return list(rows)

    def query_one(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any] | None:
        """Run a SELECT expected to return at most one row."""
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def query_value(
        self, sql: str, params: Sequence[Any] | None = None, default: Any = None
    ) -> Any:
        """Return the first column of the first row, or ``default``."""
        row = self.query_one(sql, params)
        if not row:
            return default
        value = next(iter(row.values()), default)
        return default if value is None else value

    def execute(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> int:
        """Run an INSERT/UPDATE/DELETE and return the affected row count."""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(sql, tuple(params or ()))
                affected = cursor.rowcount
            finally:
                cursor.close()
        with self._lock:
            self._query_count += 1
        self._set_state(True)
        return int(affected)

    def insert(self, sql: str, params: Sequence[Any] | None = None) -> int:
        """Run an INSERT and return the generated primary key."""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(sql, tuple(params or ()))
                new_id = cursor.lastrowid
            finally:
                cursor.close()
        with self._lock:
            self._query_count += 1
        self._set_state(True)
        return int(new_id or 0)

    def execute_many(
        self, sql: str, param_sets: Iterable[Sequence[Any]]
    ) -> int:
        """Run a batched INSERT/UPDATE.

        This is what keeps live capture from issuing one round-trip per packet
        (§36, §106).
        """
        rows = [tuple(params) for params in param_sets]
        if not rows:
            return 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(sql, rows)
                affected = cursor.rowcount
            finally:
                cursor.close()
        with self._lock:
            self._query_count += 1
        self._set_state(True)
        return int(affected)

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """Run several statements atomically.

        Yields a cursor; the transaction commits on clean exit and rolls back
        on any exception.
        """
        with self.connection() as conn:
            previous_autocommit = conn.autocommit
            conn.autocommit = False
            cursor = conn.cursor(dictionary=True)
            try:
                yield cursor
                conn.commit()
                self._set_state(True)
            except Exception:
                try:
                    conn.rollback()
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Transaction rollback failed")
                raise
            finally:
                cursor.close()
                try:
                    conn.autocommit = previous_autocommit
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def ping(self) -> bool:
        """Probe connectivity with ``SELECT 1``.

        Returns:
            True when the server answered. Never raises: this is called from a
            scheduled health probe that must not crash the scheduler.
        """
        try:
            value = self.query_value("SELECT 1 AS ok")
            ok = bool(value)
            self._set_state(ok, "" if ok else "SELECT 1 returned no result")
            return ok
        except (DatabaseError, Exception) as exc:  # noqa: BLE001
            self._set_state(False, str(exc))
            return False

    def server_version(self) -> str:
        """MySQL server version string, or an empty string when unreachable."""
        try:
            return str(self.query_value("SELECT VERSION() AS v", default="") or "")
        except Exception:  # noqa: BLE001
            return ""

    def table_names(self) -> set[str]:
        """Tables present in the configured schema."""
        try:
            rows = self.query(
                "SELECT table_name AS name FROM information_schema.tables "
                "WHERE table_schema = %s",
                (self._settings.database,),
            )
        except Exception:  # noqa: BLE001
            return set()
        return {str(row["name"]) for row in rows}

    def database_size_bytes(self) -> int:
        """Approximate on-disk size of the schema, from information_schema."""
        try:
            value = self.query_value(
                "SELECT COALESCE(SUM(data_length + index_length), 0) AS size "
                "FROM information_schema.tables WHERE table_schema = %s",
                (self._settings.database,),
                default=0,
            )
            return int(value or 0)
        except Exception:  # noqa: BLE001
            return 0

    def table_row_counts(self) -> dict[str, int]:
        """Row estimates per table, for the maintenance screen."""
        try:
            rows = self.query(
                "SELECT table_name AS name, table_rows AS rows_estimate "
                "FROM information_schema.tables WHERE table_schema = %s",
                (self._settings.database,),
            )
        except Exception:  # noqa: BLE001
            return {}
        return {str(r["name"]): int(r["rows_estimate"] or 0) for r in rows}

    def pool_status(self) -> dict[str, Any]:
        """Real pool counters for the System Health screen."""
        with self._lock:
            return {
                "configured_size": self._settings.pool_size,
                "open_connections": self._created,
                "idle_connections": self._pool.qsize(),
                "queries_executed": self._query_count,
                "connected": bool(self._connected),
                "last_error": self._last_error,
                "last_success": self._last_success,
            }


def server_reachable(settings: DatabaseSettings) -> tuple[bool, str]:
    """Attempt a one-off connection without creating a pool.

    Used by the first-run wizard and the ``health_check`` script.

    Returns:
        ``(reachable, detail)`` where detail carries the driver's own error
        text when the attempt failed.
    """
    if not MYSQL_AVAILABLE:
        return False, f"mysql-connector-python not installed: {MYSQL_IMPORT_ERROR}"
    try:
        connection = mysql.connector.connect(
            host=settings.host,
            port=settings.port,
            user=settings.user,
            password=settings.password,
            connection_timeout=settings.connect_timeout,
        )
    except MySQLError as exc:
        return False, str(exc)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        cursor.close()
        return True, str(version[0]) if version else "connected"
    finally:
        connection.close()
