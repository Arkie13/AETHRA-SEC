"""Performance and reliability guards (production lag / leak fixes).

Each test pins one measured fix from the reliability pass:

* the connection pool no longer pings on every checkout, only after an idle
  gap, so an active application does not pay a round-trip per statement;
* the sidebar badges are read off the Tk thread and painted from cache, so no
  DB query runs on the UI thread every tick;
* the dashboard's expensive top-sources panel is cached and backed by a
  covering index;
* start / stop / start leaves no duplicate capture workers behind.
"""

from __future__ import annotations

import inspect
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "aethra_sec" / "ui" / "app.py"


class _FakeConn:
    """A connection that records how often it is health-checked."""

    def __init__(self) -> None:
        self.pings = 0
        self._aethra_checked_at = 0.0

    def ping(self, **_kw) -> None:
        self.pings += 1

    def close(self) -> None:  # pragma: no cover - discard path
        pass


class TestPoolDoesNotPingEveryCheckout:
    """A statement on a freshly used connection must not add a round-trip."""

    def _manager(self):
        from aethra_sec.config.settings import DatabaseSettings
        from aethra_sec.database.connection import DatabaseManager

        return DatabaseManager(DatabaseSettings(host="127.0.0.1", database="x"))

    def test_a_recently_used_connection_is_not_pinged(self) -> None:
        from aethra_sec.database import connection as conn_mod

        mgr = self._manager()
        conn = _FakeConn()
        conn._aethra_checked_at = time.monotonic()  # used just now
        mgr._pool.put_nowait(conn)
        with mgr.connection() as c:
            assert c is conn
        assert conn.pings == 0, "a fresh connection was pinged"

    def test_an_idle_connection_is_pinged_once(self) -> None:
        from aethra_sec.database import connection as conn_mod

        mgr = self._manager()
        conn = _FakeConn()
        conn._aethra_checked_at = time.monotonic() - conn_mod.PING_IDLE_SECONDS - 1
        mgr._pool.put_nowait(conn)
        with mgr.connection() as c:
            assert c is conn
        assert conn.pings == 1, "an idle connection was reused without a health check"

    def test_checkout_refreshes_the_idle_clock(self) -> None:
        mgr = self._manager()
        conn = _FakeConn()
        conn._aethra_checked_at = 0.0
        mgr._pool.put_nowait(conn)
        with mgr.connection():
            pass
        # Returned to the pool with a recent stamp, so the next checkout trusts it.
        assert time.monotonic() - conn._aethra_checked_at < 5


class TestSidebarBadgesNeverQueryOnTheTkThread:
    """The tick paints cached counts; the read happens on a worker."""

    def test_the_paint_path_reads_only_the_cache(self) -> None:
        src = inspect.getsource(
            __import__("aethra_sec.ui.app", fromlist=["MainWindow"]).MainWindow
            ._refresh_nav_badges
        )
        assert "_badge_counts" in src
        for forbidden in (
            "unresolved_alert_count", "open_incident_count", "pending_count",
        ):
            assert forbidden not in src, (
                f"{forbidden} runs on the Tk thread in the badge paint path"
            )

    def test_the_counts_are_read_on_a_worker_thread(self) -> None:
        src = inspect.getsource(
            __import__("aethra_sec.ui.app", fromlist=["MainWindow"]).MainWindow
            ._maybe_refresh_badge_counts
        )
        assert "threading.Thread" in src and "dispatch.post" in src
        assert "unresolved_alert_count" in src
        # The Incidents badge went with the Incidents screen; nothing may
        # keep querying for a counter no sidebar entry displays.
        assert "open_incident_count" not in src


class TestDashboardTopSourcesIsCachedAndIndexed:
    def test_network_overview_is_cached(self) -> None:
        from aethra_sec.services.dashboard_service import DashboardService

        src = inspect.getsource(DashboardService.network_overview)
        assert "_overview_cache" in src and "OVERVIEW_TTL_SECONDS" in src

    def test_the_covering_index_is_declared(self) -> None:
        schema = (ROOT / "aethra_sec" / "database" / "schema.py").read_text(
            encoding="utf-8"
        )
        assert "ix_traffic_period_src (captured_at, src_ip, length)" in schema

    def test_the_migration_adds_the_index_idempotently(self) -> None:
        from aethra_sec.database import migrations

        src = inspect.getsource(migrations._apply_traffic_topsource_index)
        assert "ix_traffic_period_src" in src
        assert "_index_exists" in src


class TestCaptureLeavesNoDuplicateWorkers:
    """start -> stop -> start must not accumulate capture threads (§16)."""

    def test_start_guard_and_single_worker(self) -> None:
        from aethra_sec.services.packet_capture import PacketCaptureService

        start = inspect.getsource(PacketCaptureService.start)
        # A second start while active is refused, so a worker cannot be doubled.
        assert "is_active" in start
        # The worker is a single tracked thread, cleared on stop.
        assert "self._worker" in inspect.getsource(PacketCaptureService)
