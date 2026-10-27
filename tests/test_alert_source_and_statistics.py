"""AETHRA-SEC-only Alerts, Attack Statistics, prompt notifications and scan
episodes (15 Oct 2026 revision, part 3 - TEST A-L).

Everything runs against the isolated test schema with synthetic records and
in-process packets. Nothing is sent on a network and nothing reaches the
application database.
"""

from __future__ import annotations

import statistics
import threading
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    RULE_HTTP_FLOOD,
    RULE_ICMP_FLOOD,
    RULE_PORT_SCAN,
    RULE_SYN_FLOOD,
    RULE_UDP_FLOOD,
)
from aethra_sec.analytics.attack_categories import (
    CATEGORIES,
    HTTP,
    ICMP,
    PORT_SCAN,
    TCP,
    UDP,
    snort_signature,
    summarise,
)
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.models.traffic import CapturedPacket
from test_repeated_attack_episodes import (  # the shared pipeline harness
    Pipeline,
    _correlation,
    _Settings,
    icmp_burst,
)

NOW = datetime.now(UTC)


def _anomaly(rule: str, *, src="10.98.0.10", dst="10.98.0.20", at=None,
             severity=Severity.MEDIUM, category=ThreatCategory.UNCLASSIFIED) -> TrafficAnomaly:
    at = at or NOW - timedelta(minutes=10)
    return TrafficAnomaly(
        rule_id=rule, category=category, title="TEST FIXTURE - not a real detection",
        severity=severity, src_ip=src, dst_ip=dst, protocol="TCP",
        observed_value=600.0, threshold_value=120.0, window_seconds=5,
        detected_at=at, first_seen=at, last_seen=at + timedelta(seconds=8),
        source=EvidenceSource.PYSHARK, created_at=at,
        evidence={"measurement_clock": "packet"},
    )


def _snort(sid: int, rev: int, message: str, *, src="10.98.0.10", dst="10.98.0.20",
           dst_port=None, at=None, duplicates=1, protocol="TCP") -> SnortAlert:
    at = at or NOW - timedelta(minutes=10)
    return SnortAlert(
        alert_time=at, received_at=at, generator_id=1, signature_id=sid,
        revision=rev, message=message, priority=3, severity=Severity.LOW,
        protocol=protocol, src_ip=src, dst_ip=dst, dst_port=dst_port,
        dedup_key=f"1:{sid}:{src}:{dst}:{dst_port or ''}", created_at=at,
        duplicate_count=duplicates,
    )


class _Access:
    def require(self, *_a, **_k):
        return SimpleNamespace()


def _snort_service(db):  # noqa: ANN001
    from aethra_sec.services.snort_service import SnortService

    service = SnortService.__new__(SnortService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._access = _Access()  # noqa: SLF001
    return service


# ---------------------------------------------------------------------------
# TEST A - source filtering
# ---------------------------------------------------------------------------
class TestA_SourceFiltering:
    def test_the_primary_view_loads_and_counts_aethra_detections_only(self) -> None:
        from aethra_sec.ui.screens.alerts import SOURCE_AETHRA, SOURCE_SNORT, AlertsScreen

        calls = []

        class Snort:
            def search(self, *_a, **_k):
                calls.append("snort.search")
                return ["SNORT-ROW"]

            def search_anomalies(self, *_a, **_k):
                calls.append("search_anomalies")
                return ["AETHRA-ROW"]

            def aethra_detection_totals(self, *_a, **_k):
                calls.append("aethra_totals")
                return {"total": 1}

            def snort_evidence_totals(self, *_a, **_k):
                calls.append("snort_totals")
                return {"total": 1}

        class Harness(AlertsScreen):
            session = object()
            is_alive = True

        def run(source: str):
            screen = object.__new__(Harness)
            screen.context = SimpleNamespace(snort=Snort(), dashboard=None)
            screen._update_snort_status = lambda: None  # noqa: SLF001
            var = SimpleNamespace(get=lambda: "All")
            screen._search_var = SimpleNamespace(get=lambda: "")  # noqa: SLF001
            screen._severity_var = screen._status_var = var  # noqa: SLF001
            screen._source_var = SimpleNamespace(get=lambda: source)  # noqa: SLF001
            screen._selected_period = lambda: None  # noqa: SLF001
            screen.status = lambda _m: None
            captured = {}
            screen.run_async = lambda work, *a, **k: captured.setdefault("work", work)
            screen.refresh()
            return captured["work"]()

        calls.clear()
        alerts, anomalies, _totals, _rates = run(SOURCE_AETHRA)
        assert alerts == [] and anomalies == ["AETHRA-ROW"]
        assert "snort.search" not in calls and "snort_totals" not in calls
        calls.clear()
        alerts, anomalies, _totals, _rates = run(SOURCE_SNORT)
        assert alerts == ["SNORT-ROW"] and anomalies == []
        assert "search_anomalies" not in calls and "aethra_totals" not in calls

    def test_aethra_totals_never_include_snort_rows(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        repo.insert_anomaly(_anomaly(RULE_ICMP_FLOOD, severity=Severity.HIGH))
        repo.insert_alert(_snort(1000002, 2, "TCP SYN (any port)"))
        service = _snort_service(clean_db)
        aethra = service.aethra_detection_totals(object(), {})
        snort = service.snort_evidence_totals(object(), {})
        assert aethra["total"] == 1 and aethra.get("HIGH") == 1
        assert snort["total"] == 1 and snort.get("LOW") == 1
        assert service.unreviewed_detection_count(object()) == 1

    def test_a_snort_alert_raises_no_popup_by_default(self) -> None:
        from aethra_sec.services.notification_service import NotificationService

        created = []

        class Repo:
            def create(self, notification):
                created.append(notification)
                return len(created)

            def exists_since(self, *_a):
                return False

            def prune_excess(self, *_a):
                return 0

        class Settings:
            def get_bool(self, key, default=False):
                return default

            def get_int(self, key, default=0):
                return default

            def get_str(self, key, default=""):
                return "LOW" if key == "notifications.min_severity" else default

        bus = EventBus()
        announced = []
        bus.subscribe((EventType.NOTIFICATION_STORED,), announced.append,
                      queued=False, name="test")
        service = NotificationService(Repo(), Repo(), Settings(), bus)
        alert = _snort(1000007, 2, "TCP SYN flood - possible DoS")
        alert.id, alert.severity = 77, Severity.HIGH
        bus.publish(EventType.SNORT_ALERT_RECEIVED, SimpleNamespace(alert=alert))
        assert created == [] and announced == []
        assert service.snort_evidence_only == 1
        anomaly = _anomaly(RULE_SYN_FLOOD, severity=Severity.HIGH)
        anomaly.id = 5
        bus.publish(EventType.TRAFFIC_ANOMALY_DETECTED, SimpleNamespace(anomaly=anomaly))
        assert len(created) == 1 and len(announced) == 1, "AETHRA-SEC still notifies"

    def test_snort_evidence_stays_inspectable_from_the_detection(self, clean_db) -> None:
        from aethra_sec.ui.screens.alerts import snort_evidence_section

        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(RULE_ICMP_FLOOD))
        alert = _snort(1000006, 2, "ICMP flood - possible ping flood/DoS",
                       protocol="ICMP", duplicates=12)
        alert_id = repo.insert_alert(alert)
        repo.db.execute("INSERT INTO incidents (reference, title, category, severity, "
                        "status, correlation_key, first_seen, last_seen, created_at) "
                        "VALUES ('INC-T', 't', 'ICMP_FLOOD', 'LOW', 'NEW', 'k', "
                        "UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))")
        incident = repo.db.query_one("SELECT id FROM incidents WHERE reference='INC-T'")["id"]
        repo.set_anomaly_incident(anomaly_id, incident)
        repo.set_alert_incident(alert_id, incident)
        anomaly = repo.get_anomaly(anomaly_id)
        section = snort_evidence_section(
            anomaly, _snort_service(clean_db).snort_evidence_for_attack(object(), incident)
        )
        rows = dict(section.rows)
        assert rows["Snort records linked"].startswith("1")
        assert rows["Raw Snort alerts"].startswith("12")
        assert "1000006" in section.body


# ---------------------------------------------------------------------------
# TEST B - one episode per category
# ---------------------------------------------------------------------------
class TestB_CategoryCounts:
    def test_one_episode_in_each_category(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        for rule in (RULE_SYN_FLOOD, RULE_HTTP_FLOOD, RULE_UDP_FLOOD,
                     RULE_ICMP_FLOOD, RULE_PORT_SCAN):
            repo.insert_anomaly(_anomaly(rule))
        repo.insert_anomaly(_anomaly(RULE_HOST_SWEEP))
        repo.insert_alert(_snort(1000007, 2, "TCP SYN flood - possible DoS", duplicates=30))
        repo.insert_alert(_snort(1000002, 2, "TCP SYN (any port)", dst_port=22, duplicates=4))
        stats = summarise(
            repo.aethra_episode_statistics(None, None, NOW),
            repo.snort_signature_statistics(None, None),
        )
        by = {row.category: row for row in stats.rows}
        assert {c: by[c].aethra_episodes for c in CATEGORIES} == {
            TCP: 1, HTTP: 1, UDP: 1, ICMP: 1, PORT_SCAN: 1}
        assert stats.aethra_total == 5, "the host sweep is not a port scan"
        assert stats.host_sweep_episodes == 1
        assert by[TCP].snort_attack_raw == 30 and by[TCP].snort_attack_records == 1
        assert by[TCP].snort_observation_raw == 4, "per-packet rows kept apart"
        assert by[PORT_SCAN].snort_attack_raw is None, "no Snort port-scan rule"
        assert by[HTTP].snort_attack_raw is None, "no Snort HTTP request rule"

    def test_mapping_uses_identifiers_and_revisions(self) -> None:
        assert snort_signature(1, 1000002, 2).is_attack_rule is False
        assert snort_signature(1, 1000002, 1) is None, "conflicting evidence -> OTHER"
        assert snort_signature(1, 1000009, 2).category == TCP


# ---------------------------------------------------------------------------
# TEST C - one port scan, 500 raw records
# ---------------------------------------------------------------------------
def _scan_packets(start: datetime, *, src: str, targets: tuple[str, ...], ports: int):
    for t_index, target in enumerate(targets):
        for port in range(ports):
            yield CapturedPacket(
                captured_at=start + timedelta(seconds=t_index * 2 + port * 0.004),
                src_ip=src, dst_ip=target, protocol="TCP", src_port=40000 + port,
                dst_port=1 + port, tcp_flags=0x02)


class TestC_OnePortScanFiveHundredRecords:
    def test_one_scan_is_one_result_with_its_raw_evidence(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        start = datetime.now(UTC) - timedelta(minutes=3)
        targets = ("10.98.1.21", "10.98.1.22", "10.98.1.23")
        pipeline.feed(_scan_packets(start, src="10.98.1.10", targets=targets, ports=200))
        scans = pipeline.rows(RULE_PORT_SCAN)
        assert len(scans) == 1, "one scanner, one scan episode across its targets"
        evidence = scans[0].evidence
        assert sorted(evidence["scan_targets"]) == sorted(targets)
        assert len(evidence["ports_observed"]) >= 20

        repo = AlertRepository(clean_db)
        for port in range(500):  # one Snort row per probed port
            repo.insert_alert(_snort(1000002, 2, "TCP SYN (any port)", src="10.98.1.10",
                                     dst=targets[port % 3], dst_port=1 + port,
                                     at=start + timedelta(seconds=1 + port * 0.01)))
        correlation, incidents = _correlation(
            clean_db, _Settings(**{"correlation.flood_grace_seconds": 0}))
        correlation.correlate_recent()
        attacks = incidents.search(limit=1000)
        scan_attack = [i for i in attacks if str(i.category) == "PORT_SCAN"]
        assert len(scan_attack) == 1
        linked = repo.db.query_one(
            "SELECT COUNT(*) c FROM snort_alerts WHERE incident_id = %s",
            (scan_attack[0].id,))["c"]
        assert linked == 500, "every raw record kept and linked as evidence"
        assert repo.db.query_one("SELECT COUNT(*) c FROM snort_alerts")["c"] == 500

        stats = summarise(repo.aethra_episode_statistics(None, None, NOW),
                          repo.snort_signature_statistics(None, None))
        by = {row.category: row for row in stats.rows}
        assert by[PORT_SCAN].aethra_episodes == 1
        assert by[PORT_SCAN].correlated == 1
        assert by[TCP].snort_observation_raw == 500
        assert stats.aethra_total == 1


# ---------------------------------------------------------------------------
# TEST D - repeated ingestion
# ---------------------------------------------------------------------------
class TestD_RepeatedIngestion:
    def test_the_same_lines_and_cycles_change_nothing(self, clean_db) -> None:
        from test_repeated_attack_episodes import _snort_line, _snort_service as ingest

        service = ingest(clean_db)
        repo = AlertRepository(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        lines = [_snort_line(t + timedelta(seconds=s)) for s in (0, 5, 60)]
        for _ in range(3):
            for line in lines:
                service._on_alert(line, "file")  # noqa: SLF001
        assert repo.db.query_one("SELECT COUNT(*) c FROM snort_alerts")["c"] == 2
        before = summarise(repo.aethra_episode_statistics(None, None, NOW),
                           repo.snort_signature_statistics(None, None))
        correlation, incidents = _correlation(clean_db)
        for _ in range(3):
            correlation.correlate_recent()
        after = summarise(repo.aethra_episode_statistics(None, None, NOW),
                          repo.snort_signature_statistics(None, None))
        assert before == after
        published = [p for p in service._bus.published  # noqa: SLF001
                     if p[0] is EventType.SNORT_ALERT_RECEIVED]
        assert len(published) == 2, "only the two new alerts were ever announced"


# ---------------------------------------------------------------------------
# TEST E - two distinct scans
# ---------------------------------------------------------------------------
class TestE_TwoScans:
    def test_scans_separated_by_the_gap_are_two_results(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        start = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(_scan_packets(start, src="10.98.2.10", targets=("10.98.2.21",), ports=100))
        pipeline.feed(_scan_packets(start + timedelta(seconds=60), src="10.98.2.10",
                                    targets=("10.98.2.21",), ports=100))
        scans = pipeline.rows(RULE_PORT_SCAN)
        assert len(scans) == 2
        assert scans[0].last_seen < scans[1].first_seen


# ---------------------------------------------------------------------------
# TEST F / G - continuous and repeated floods (rule-level detail in
# test_repeated_attack_episodes.py; here: one result per episode per protocol)
# ---------------------------------------------------------------------------
class TestFG_EpisodesPerProtocol:
    def test_continuous_and_repeated_floods(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=10)
        for run in range(2):  # two runs of each, 40 s apart
            base = t + timedelta(seconds=run * 40)
            packets = list(icmp_burst(base, 10, 300, src="10.98.3.10", dst="10.98.3.20",
                                      replies=False))
            for i in range(4000):
                at = base + timedelta(seconds=i / 400.0)
                packets.append(CapturedPacket(captured_at=at, src_ip="10.98.3.10",
                                              dst_ip="10.98.3.20", protocol="UDP",
                                              src_port=40000, dst_port=9999))
                if i < 3000:
                    packets.append(CapturedPacket(captured_at=at, src_ip="10.98.3.10",
                                                  dst_ip="10.98.3.20", protocol="TCP",
                                                  src_port=1024 + i, dst_port=80,
                                                  tcp_flags=0x02))
            pipeline.feed(sorted(packets, key=lambda p: p.captured_at))
        for rule in (RULE_ICMP_FLOOD, RULE_UDP_FLOOD, RULE_SYN_FLOOD):
            rows = pipeline.rows(rule, "10.98.3.10")
            assert len(rows) == 2, (rule, len(rows))
            assert all(r.event_count > 3 for r in rows), "measurements folded, not rows"


# ---------------------------------------------------------------------------
# TEST H - date filters
# ---------------------------------------------------------------------------
class TestH_DateFilters:
    def test_today_last_24_hours_and_all_time(self, clean_db) -> None:
        from aethra_sec.models.periods import period_for_range

        now = datetime.now(UTC)
        today = period_for_range("Today", now)
        day = period_for_range("Last 24 hours", now)
        repo = AlertRepository(clean_db)
        stamps = {
            "today": max(today.start + timedelta(seconds=1), now - timedelta(minutes=2)),
            "within_24h": now - timedelta(hours=23),
            "old": now - timedelta(days=3),
        }
        for name, at in stamps.items():
            repo.insert_anomaly(_anomaly(RULE_ICMP_FLOOD, src=f"10.98.4.{len(name)}", at=at))

        def count(period):
            start = getattr(period, "start", None)
            end = getattr(period, "end", None)
            return summarise(repo.aethra_episode_statistics(start, end, now), []).aethra_total

        assert count(period_for_range("All data", now)) == 3
        assert count(day) == 2
        expected_today = 1 + (1 if stamps["within_24h"] >= today.start else 0)
        assert count(today) == expected_today


# ---------------------------------------------------------------------------
# TEST I / J - notification latency through the real delivery path
# ---------------------------------------------------------------------------
def notification_latency(db, tk_root, *, episodes: int, prompt: bool,  # noqa: ANN001
                         source: str = "10.98.5.10"):
    """Drive episodes through engine -> storage -> notification -> popup.

    The capture side runs on a worker thread, as in the application; the
    popup is the real ToastManager on a real Tk root, drained either by the
    revised wake-up (``prompt``) or only by a 2,000 ms tick, which is how the
    application delivered notifications before.
    """
    from aethra_sec.database.repositories.settings import ErrorRepository, NotificationRepository
    from aethra_sec.services.notification_service import NotificationService
    from aethra_sec.ui import dispatch
    from aethra_sec.ui.app import _NOTIFICATION_EVENTS, MainWindow
    from aethra_sec.ui.theme import apply_theme
    from aethra_sec.ui.widgets.toast import ToastManager

    fonts = apply_theme(tk_root)
    dispatch.ensure(tk_root)
    bus = EventBus()
    marks: dict[int, dict[str, float]] = {}
    pipeline = Pipeline(db)
    pipeline.service._bus = bus  # noqa: SLF001
    settings = _Settings(**{"notifications.min_severity": "LOW"})
    NotificationService(NotificationRepository(db), ErrorRepository(db), settings, bus)

    insert = pipeline.repo.insert_anomaly
    pipeline.service._alerts.insert_anomaly = lambda a: (  # noqa: SLF001
        lambda new_id: (marks.setdefault(new_id, {}).update(stored=time.perf_counter()), new_id)[1]
    )(insert(a))

    def on_stored(event):  # noqa: ANN001
        ref = getattr(event.payload, "reference_id", None)
        if ref is not None:
            marks.setdefault(int(ref), {})["notified"] = time.perf_counter()

    bus.subscribe(_NOTIFICATION_EVENTS, on_stored, queued=False, name="latency-probe")

    window = object.__new__(MainWindow)
    window.root = tk_root
    window.context = SimpleNamespace(event_bus=bus, audio_alerts=None, notifications=None)
    window._closing = False  # noqa: SLF001
    toasts = ToastManager(tk_root, fonts)
    window._toasts = toasts  # noqa: SLF001
    window.set_status = lambda _m: None
    window.refresh_notifications = lambda: None
    window.navigate = lambda *_a, **_k: None
    window._notification_wake_pending = False  # noqa: SLF001
    window._notification_subscription = bus.subscribe(  # noqa: SLF001
        _NOTIFICATION_EVENTS, window._on_notification_event, queued=True,  # noqa: SLF001
        max_size=512, name="main-window-notifications")
    if prompt:
        bus.subscribe(_NOTIFICATION_EVENTS, window._wake_for_notification,  # noqa: SLF001
                      queued=False, name="wake")

    real_show = toasts.show_persistent

    def show(*args, **kwargs):  # noqa: ANN001
        shown = real_show(*args, **kwargs)
        tk_root.update_idletasks()
        ref = str(kwargs.get("reference", ""))  # e.g. "Traffic anomaly #12"
        anomaly_id = int(ref.rsplit("#", 1)[-1]) if "#" in ref else None
        if anomaly_id is not None:
            marks.setdefault(anomaly_id, {})["visible"] = time.perf_counter()
        frame = toasts.persistent_frame
        if frame is not None:
            toasts.close_persistent(frame, advance=False)
        return shown

    toasts.show_persistent = show
    fired_at: dict[int, float] = {}
    done = threading.Event()
    base = datetime.now(UTC) - timedelta(minutes=30)

    def capture_worker():
        for n in range(episodes):
            for packet in icmp_burst(base + timedelta(seconds=n * 25), 6, 300,
                                     src=source, dst="10.98.5.20", replies=False):
                for anomaly in pipeline.engine.evaluate(packet):
                    t_fire = time.perf_counter()
                    pipeline.service._store_anomaly(anomaly)  # noqa: SLF001
                    if anomaly.starts_episode and anomaly.id is not None:
                        fired_at[anomaly.id] = t_fire
            time.sleep(0.15)  # a quiet moment between runs, as on the wire
        done.set()

    def old_tick():
        bus.dispatch(window._notification_subscription, 500)  # noqa: SLF001
        if not done.is_set() or bus.pending(window._notification_subscription):  # noqa: SLF001
            tk_root.after(2000, old_tick)

    if not prompt:
        tk_root.after(2000, old_tick)
    threading.Thread(target=capture_worker, daemon=True).start()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        tk_root.update()
        time.sleep(0.005)
        if done.is_set() and all("visible" in marks.get(i, {}) for i in fired_at):
            break
    samples = []
    for anomaly_id, t_fire in fired_at.items():
        m = marks.get(anomaly_id, {})
        if {"stored", "notified", "visible"} <= set(m):
            samples.append({
                "store": m["stored"] - t_fire,
                "notify": m["notified"] - m["stored"],
                "deliver": m["visible"] - m["notified"],
                "total": m["visible"] - t_fire,
            })
    return samples


def describe(samples: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    out = {}
    for key in ("store", "notify", "deliver", "total"):
        values = sorted(s[key] for s in samples)
        out[key] = {
            "n": len(values),
            "median_ms": round(statistics.median(values) * 1000, 1),
            "p95_ms": round(values[min(len(values) - 1, int(0.95 * len(values)))] * 1000, 1),
            "max_ms": round(values[-1] * 1000, 1),
        }
    return out


class TestIJ_NotificationLatency:
    def test_eligible_detections_reach_a_visible_popup_promptly(self, clean_db, tk_root) -> None:
        samples = notification_latency(clean_db, tk_root, episodes=30, prompt=True)
        assert len(samples) == 30, "every episode was announced"
        stats = describe(samples)
        assert stats["total"]["p95_ms"] < 1000, stats
        assert stats["deliver"]["p95_ms"] < 500, stats


# ---------------------------------------------------------------------------
# TEST K / L - queries, failure display and the screen itself
# ---------------------------------------------------------------------------
class TestKL_StatisticsScreen:
    def test_the_screen_opens_shows_real_counts_and_never_a_failed_zero(self, tk_root) -> None:
        from aethra_sec.ui import dispatch
        from aethra_sec.ui.app import NAV_GROUPS, NAVIGATION
        from aethra_sec.ui.screens.attack_statistics import AttackStatisticsScreen
        from aethra_sec.ui.theme import apply_theme

        assert "attack_statistics" in dict(NAV_GROUPS)["SECURITY"]
        assert ("attack_statistics", "Attack Statistics") in [(k, l) for k, l, _p in NAVIGATION]
        fonts = apply_theme(tk_root)
        dispatch.ensure(tk_root)

        class Snort:
            fail = False

            def attack_statistics(self, *_a):
                if self.fail:
                    raise RuntimeError("database unavailable")
                return {"aethra": [{"rule_id": RULE_PORT_SCAN, "episodes": 2, "active": 1,
                                    "correlated": 1, "revised": 2, "latest": NOW}],
                        "snort": [{"generator_id": 1, "signature_id": 1000002,
                                   "revision": 2, "records": 500, "raw_alerts": 640,
                                   "latest": NOW}]}

        snort = Snort()
        statuses = []
        app = SimpleNamespace(context=SimpleNamespace(snort=snort, current_session=object(),
                                                      settings_service=None, access=None),
                              fonts=fonts, set_status=statuses.append,
                              navigate=lambda *a, **k: None)
        screen = AttackStatisticsScreen(tk_root, app)
        screen.build()

        def pump():
            end = time.monotonic() + 5
            count = len(statuses)
            while time.monotonic() < end and len(statuses) < count + 2:
                tk_root.update()
                time.sleep(0.02)

        screen.refresh(); pump()
        rows = {r["category"]: r for r in screen._table._rows.values()}  # noqa: SLF001
        assert rows["PORT SCAN"]["episodes"] == "2"
        assert rows["TCP"]["snort_obs"] == "640"
        assert rows["HTTP"]["snort_raw"] == "no rule"
        text = screen._totals.get("1.0", "end")  # noqa: SLF001
        assert "Unique AETHRA-SEC attack episodes (5 categories): 2" in text

        snort.fail = True
        screen.refresh(); pump()
        text = screen._totals.get("1.0", "end")  # noqa: SLF001
        assert "Statistics unavailable" in text and screen._table._rows == {}  # noqa: SLF001
        screen.destroy()
