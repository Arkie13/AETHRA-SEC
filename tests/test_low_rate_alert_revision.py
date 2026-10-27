"""Low-rate alert revision, 19 Oct 2026 (TEST A-L, plus TEST S for the defect).

The report: alerts kept appearing "at 1.5 PPS". They were RULE-HOST-SWEEP
records from 192.168.1.222, which ARP-swept 192.168.1.0/24 (about 190-240
addresses over ~7.6 s) once a minute. Each sweep was recorded at the packet that
reached the 15-host threshold - "15 hosts, 1.5 pps" - and the rest of the
sweep was discarded, so a subnet sweep at ~23 pps read as an alert raised by
trivially low traffic. Port scans were frozen the same way at 20 ports.

See evaluation/low_rate_alert_revision/LOW_RATE_ALERT_ROOT_CAUSE.md.

Every packet here is a synthetic in-memory object; nothing is sent on any
network. Storage tests use the isolated test database (``clean_db``), never
the production database.
"""

from __future__ import annotations

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
    AnomalyRuleEngine,
    DetectionThresholds,
    flood_severity,
)
from aethra_sec.core.events import EventType
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.enums import Severity
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService, PipelineCounters

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)
SWEEPER = "10.98.1.222"
ATTACKER = "10.98.1.21"
TARGET = "10.98.1.26"


# ---------------------------------------------------------------------------
# Harness: packets -> rule engine -> storage, as the capture worker does
# ---------------------------------------------------------------------------
class _Settings:
    def __init__(self, **overrides) -> None:
        self.values = {
            "detection.episode_gap_seconds": 15,
            "detection.suppression_window_seconds": 120,
        }
        self.values.update(overrides)

    def get_int(self, key, default=0):  # noqa: ANN001
        return int(self.values.get(key, default))

    def get_bool(self, key, default=False):  # noqa: ANN001
        return bool(self.values.get(key, default))

    def get_str(self, key, default=""):  # noqa: ANN001
        return str(self.values.get(key, default))

    def get_float(self, key, default=0.0):  # noqa: ANN001
        return float(self.values.get(key, default))


class _Bus:
    def __init__(self) -> None:
        self.published: list[tuple] = []

    def publish(self, event_type, payload) -> None:  # noqa: ANN001
        self.published.append((event_type, payload))

    def detections(self) -> list:
        return [p for e, p in self.published if e == EventType.TRAFFIC_ANOMALY_DETECTED]


def _capture(db) -> PacketCaptureService:  # noqa: ANN001
    service = object.__new__(PacketCaptureService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._bus = _Bus()  # noqa: SLF001
    service._settings = _Settings()  # noqa: SLF001
    service._hosts = SimpleNamespace(find_id_by_ip=lambda _ip: None)  # noqa: SLF001
    service.counters = PipelineCounters()

    def no_statistics():
        raise RuntimeError("no live capture in this test")

    service.statistics = no_statistics  # type: ignore[method-assign]
    return service


class Pipeline:
    def __init__(self, db=None) -> None:  # noqa: ANN001
        self.engine = AnomalyRuleEngine(DetectionThresholds())
        self.service = _capture(db) if db is not None else None
        self.repo = AlertRepository(db) if db is not None else None
        self.emitted: list = []

    def feed(self, packets) -> "Pipeline":  # noqa: ANN001
        for packet in packets:
            for anomaly in self.engine.evaluate(packet):
                self.emitted.append(anomaly)
                if self.service is not None:
                    self.service._store_anomaly(anomaly)  # noqa: SLF001
        return self

    def opened(self, rule_id: str | None = None) -> list:
        return [a for a in self.emitted if not a.measurement_only
                and (rule_id is None or a.rule_id == rule_id)]

    def rows(self, rule_id: str | None = None) -> list:
        sql, params = "SELECT id FROM traffic_anomalies", ()
        if rule_id:
            sql, params = sql + " WHERE rule_id = %s", (rule_id,)
        found = self.repo.db.query(sql + " ORDER BY first_seen, id", params)
        return [self.repo.get_anomaly(int(r["id"])) for r in found]

    @property
    def bus(self) -> _Bus:
        return self.service._bus  # noqa: SLF001


# ---------------------------------------------------------------------------
# Synthetic packets
# ---------------------------------------------------------------------------
def every(start: datetime, seconds: float, pps: float):
    """Timestamps at exactly ``pps`` for ``seconds``."""
    step = 1.0 / pps
    return [start + timedelta(seconds=i * step) for i in range(int(round(seconds * pps)))]


def icmp(at, src=ATTACKER, dst=TARGET) -> CapturedPacket:  # noqa: ANN001
    return CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst, protocol="ICMP", icmp_type=8)


def udp(at, src=ATTACKER, dst=TARGET, port=9999) -> CapturedPacket:  # noqa: ANN001
    return CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst, protocol="UDP",
                          src_port=40000, dst_port=port)


def syn(at, src=ATTACKER, dst=TARGET, port=80) -> CapturedPacket:  # noqa: ANN001
    return CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst, protocol="TCP",
                          src_port=41000, dst_port=port, tcp_flags=0x02)


def http(at, src=ATTACKER, dst=TARGET) -> CapturedPacket:  # noqa: ANN001
    return CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst, protocol="TCP",
                          src_port=42000, dst_port=80, tcp_flags=0x18,
                          app_protocol="HTTP", http_method="GET")


def arp(at, dst, src=SWEEPER) -> CapturedPacket:  # noqa: ANN001
    return CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst, protocol="ARP", length=60)


def sweep(start: datetime, seconds: float, hosts: int = 254, src=SWEEPER,
          prefix="10.98.1."):  # noqa: ANN001
    """One ARP request to each of prefix.1..hosts, spread evenly over ``seconds``."""
    step = seconds / hosts
    return [arp(start + timedelta(seconds=i * step), f"{prefix}{i + 1}", src=src)
            for i in range(hosts)]


def peak_window_rate(stamps: list[datetime], window: float) -> float:
    """Independent N / T: most stamps inside any [t - window, t] ending on a stamp."""
    values = [s.timestamp() for s in stamps]
    best, low = 0, 0
    for high, t in enumerate(values):
        while values[low] < t - window:
            low += 1
        best = max(best, high - low + 1)
    return best / window


def ledger_peak(engine: AnomalyRuleEngine, rule_id: str, source: str) -> float | None:
    for entry in engine.near_misses():
        if entry["rule"] == rule_id and entry["source"].startswith(source):
            return float(entry["peak_rate"])
    return None


# ===========================================================================
# TEST S - the reported defect: a sweep is recorded at its threshold crossing
# ===========================================================================
class TestS_SweepAndScanRecordTheirRealExtent:
    def test_a_254_host_sweep_is_one_alert_that_reaches_its_real_extent(self) -> None:
        # Shaped like the stored 192.168.1.222 bursts: 254 hosts over ~7 s.
        p = Pipeline().feed(sweep(T0, 7.0))
        opened = p.opened(RULE_HOST_SWEEP)
        assert len(opened) == 1, "one sweep must open exactly one alert"
        assert opened[0].observed_value == 15  # the crossing itself is unchanged
        updates = [a for a in p.emitted if a.measurement_only]
        assert updates, "the running sweep must report its extent after the crossing"
        peak_hosts = max(a.observed_value for a in p.emitted)
        peak_pps = max(a.evidence["packets_per_second"] for a in p.emitted)
        assert peak_hosts >= 200, peak_hosts
        assert peak_pps >= 20.0, peak_pps  # N / T over the 10 s window
        assert peak_hosts > 15 and peak_pps > 1.5

    def test_measurement_writes_stay_bounded(self) -> None:
        p = Pipeline().feed(sweep(T0, 1.5))
        updates = [a for a in p.emitted if a.measurement_only]
        # Doubling 15 -> 30 -> 60 -> 120 -> 240, plus at most one per second.
        assert 1 <= len(updates) <= 6, len(updates)
        assert max(a.observed_value for a in p.emitted) >= 127  # at least half of 254

    def test_pps_in_the_evidence_is_its_own_n_over_t(self) -> None:
        p = Pipeline().feed(sweep(T0, 7.0))
        for anomaly in p.emitted:
            ev = anomaly.evidence
            assert ev["packets_per_second"] == pytest.approx(
                round(ev["packets_in_window"] / ev["window_seconds"], 1)
            )

    def test_a_1200_port_scan_is_not_frozen_at_20_ports(self) -> None:
        stamps = every(T0, 3.0, 400)  # 1,200 connection attempts over 3 s
        p = Pipeline().feed(syn(t, port=1 + i) for i, t in enumerate(stamps))
        assert len(p.opened(RULE_PORT_SCAN)) == 1
        assert max(a.observed_value for a in p.emitted) >= 600

    def test_stored_episode_carries_peak_latest_and_trigger(self, clean_db) -> None:
        p = Pipeline(clean_db).feed(sweep(T0, 7.0))
        rows = p.rows(RULE_HOST_SWEEP)
        assert len(rows) == 1
        row = rows[0]
        emitted_peak = max(a.observed_value for a in p.emitted)
        emitted_pps = max(a.evidence["packets_per_second"] for a in p.emitted)
        assert float(row.observed_value) == emitted_peak  # peak hosts
        assert float(row.latest_value) == p.emitted[-1].observed_value
        assert float(row.evidence["packets_per_second"]) == emitted_pps
        assert row.evidence["distinct_hosts"] == 15  # trigger evidence preserved
        assert row.evidence["peak_measurement"]["distinct_count"] == emitted_peak
        assert row.evidence["peak_measurement"]["count_unit"] == "hosts"
        assert row.event_count == len(p.emitted)
        assert str(row.severity) == str(flood_severity(emitted_pps)[0])


# ===========================================================================
# TEST A - low-rate ICMP
# ===========================================================================
class TestA_LowRateIcmp:
    def test_rate_is_measured_correctly_and_no_rule_fires(self) -> None:
        stamps = every(T0, 120.0, 1.5)  # 180 echo requests over 120 s
        p = Pipeline().feed(icmp(t) for t in stamps)
        assert p.emitted == []
        last = stamps[-1].timestamp()
        n = sum(1 for s in stamps if last - 5.0 <= s.timestamp() <= last)
        measured = p.engine._icmp[ATTACKER].count(last, 5) / 5.0  # noqa: SLF001
        assert measured == n / 5.0
        assert 1.4 <= measured <= 1.8
        assert measured < DetectionThresholds().icmp_per_second

    def test_nothing_is_stored_or_announced(self, clean_db) -> None:
        p = Pipeline(clean_db).feed(icmp(t) for t in every(T0, 120.0, 1.5))
        assert p.rows() == []
        assert p.bus.detections() == []


# ===========================================================================
# TEST B - rates below each rule's trigger
# ===========================================================================
class TestB_BelowTrigger:
    @pytest.mark.parametrize(
        ("rule_id", "make", "pps"),
        [
            (RULE_ICMP_FLOOD, icmp, 100.0),   # trigger 120 pps
            (RULE_UDP_FLOOD, udp, 250.0),     # trigger 300 pps
            (RULE_SYN_FLOOD, syn, 150.0),     # trigger 200 pps
            (RULE_HTTP_FLOOD, http, 8.0),     # trigger 10 req/s
        ],
    )
    def test_no_detection_and_the_rate_is_measured(self, rule_id, make, pps) -> None:  # noqa: ANN001
        stamps = every(T0, 20.0, pps)
        p = Pipeline().feed(make(t) for t in stamps)
        assert [a for a in p.emitted if a.rule_id == rule_id] == []
        expected = peak_window_rate(stamps, 5.0)
        recorded = ledger_peak(p.engine, rule_id, ATTACKER)
        if recorded is not None:  # the ledger keeps the peak it saw
            assert recorded == pytest.approx(expected)
        if rule_id != RULE_SYN_FLOOD:
            assert recorded is not None, "a near miss at >= 60% must be on the ledger"

    def test_below_trigger_stores_and_announces_nothing(self, clean_db) -> None:
        packets = [icmp(t) for t in every(T0, 20.0, 100.0)]
        packets += [udp(t) for t in every(T0 + timedelta(seconds=40), 20.0, 250.0)]
        p = Pipeline(clean_db).feed(sorted(packets, key=lambda x: x.captured_at))
        assert p.rows() == []
        assert p.bus.detections() == []


# ===========================================================================
# TEST C - exactly at the trigger
# ===========================================================================
class TestC_ExactThreshold:
    def _icmp_burst(self, count: int) -> Pipeline:
        step = 4.9 / (count - 1)  # all inside one 5 s window
        return Pipeline().feed(icmp(T0 + timedelta(seconds=i * step)) for i in range(count))

    def test_600_in_5_s_is_120_pps_and_fires(self) -> None:
        p = self._icmp_burst(600)
        opened = p.opened(RULE_ICMP_FLOOD)
        assert len(opened) == 1
        assert opened[0].observed_value == 120.0
        assert opened[0].threshold_value == 120.0
        assert "600 ICMP packet(s) in 5 second(s) (120.0 packets/second)" in opened[0].observation
        assert "threshold of 120 per second" in opened[0].observation

    def test_599_in_5_s_is_119_8_pps_and_does_not(self) -> None:
        assert self._icmp_burst(599).opened(RULE_ICMP_FLOOD) == []

    @pytest.mark.parametrize(("hosts", "fires"), [(15, True), (14, False)])
    def test_sweep_boundary(self, hosts, fires) -> None:  # noqa: ANN001
        p = Pipeline().feed(sweep(T0, 2.0, hosts=hosts))
        assert bool(p.opened(RULE_HOST_SWEEP)) is fires

    @pytest.mark.parametrize(("ports", "fires"), [(20, True), (19, False)])
    def test_port_scan_boundary(self, ports, fires) -> None:  # noqa: ANN001
        p = Pipeline().feed(syn(T0 + timedelta(seconds=i * 0.2), port=100 + i)
                            for i in range(ports))
        assert bool(p.opened(RULE_PORT_SCAN)) is fires


# ===========================================================================
# TEST D - above the trigger
# ===========================================================================
class TestD_AboveThreshold:
    def test_one_record_with_rate_window_and_independent_severity(self, clean_db) -> None:
        p = Pipeline(clean_db)
        p.feed(icmp(t, src="10.98.2.1") for t in every(T0, 10.0, 200.0))
        p.feed(icmp(t, src="10.98.2.2") for t in every(T0 + timedelta(minutes=2), 6.0, 700.0))
        rows = p.rows(RULE_ICMP_FLOOD)
        assert [r.src_ip for r in rows] == ["10.98.2.1", "10.98.2.2"]
        low, medium = rows
        assert low.window_seconds == medium.window_seconds == 5
        assert float(low.threshold_value) == 120.0
        assert 120.0 <= float(low.observed_value) < 500.0
        assert str(low.severity) == "LOW"  # 200 pps: above the trigger, LOW band
        assert 500.0 <= float(medium.observed_value) < 1000.0
        assert str(medium.severity) == "MEDIUM"
        assert low.evidence["observed_rate_pps"] >= 120.0


# ===========================================================================
# TEST E - severity bands
# ===========================================================================
class TestE_SeverityBoundaries:
    @pytest.mark.parametrize(
        ("rate", "expected"),
        [(499.9, Severity.LOW), (500.0, Severity.MEDIUM),
         (999.9, Severity.MEDIUM), (1000.0, Severity.HIGH)],
    )
    def test_bands(self, rate, expected) -> None:  # noqa: ANN001
        assert flood_severity(rate)[0] == expected

    def test_a_band_label_is_not_a_detection(self) -> None:
        # 100 pps would grade LOW if it were a detection - it is not one.
        assert flood_severity(100.0)[0] == Severity.LOW
        p = Pipeline().feed(icmp(t) for t in every(T0, 20.0, 100.0))
        assert p.emitted == []


# ===========================================================================
# TEST F - low-rate events judged on their own criteria
# ===========================================================================
class TestF_LowRateSignatureAndBehaviour:
    def test_port_scan_fires_at_2_5_pps(self, clean_db) -> None:
        packets = [syn(T0 + timedelta(seconds=i * 0.4), port=1000 + i) for i in range(25)]
        p = Pipeline(clean_db).feed(packets)
        rows = p.rows(RULE_PORT_SCAN)
        assert len(rows) == 1
        assert float(rows[0].evidence["packets_per_second"]) <= 3.0  # low rate...
        assert float(rows[0].observed_value) >= 20  # ...and still a scan

    def test_snort_signature_at_low_rate_is_kept_as_evidence_only(self, clean_db) -> None:
        from aethra_sec.analytics.risk_engine import RiskEngine
        from aethra_sec.integrations.snort.parser import ParsedAlert
        from aethra_sec.services.snort_service import SnortService

        service = SnortService.__new__(SnortService)
        service._alerts = AlertRepository(clean_db)  # noqa: SLF001
        service._bus = _Bus()  # noqa: SLF001
        service._settings = _Settings()  # noqa: SLF001
        service._risk = RiskEngine()  # noqa: SLF001
        service._rate_probe = None  # noqa: SLF001
        service._resolve_host = lambda _ip: None  # noqa: SLF001
        service._stored = service._duplicates = service._store_failures = 0  # noqa: SLF001
        at = datetime.now(UTC) - timedelta(minutes=5)
        raw = (f"{at:%m/%d-%H:%M:%S.%f} [**] [1:1000001:1] ICMP echo request [**] "
               f"{{ICMP}} {ATTACKER} -> {TARGET}")
        service._on_alert(ParsedAlert(  # noqa: SLF001
            message="ICMP echo request", timestamp=at, generator_id=1,
            signature_id=1000001, revision=1, classification="Misc activity",
            priority=3, protocol="ICMP", src_ip=ATTACKER, dst_ip=TARGET,
            raw=raw, format="fast",
        ), "file")
        rows = clean_db.query("SELECT signature_id, message, raw_alert FROM snort_alerts")
        assert len(rows) == 1
        assert int(rows[0]["signature_id"]) == 1000001
        assert rows[0]["raw_alert"] == raw  # the sensor's own line, unchanged
        assert clean_db.query("SELECT id FROM traffic_anomalies") == []


# ===========================================================================
# TEST G - continuous low-rate traffic
# ===========================================================================
class TestG_ContinuousLowRate:
    def _ten_minutes(self) -> list[CapturedPacket]:
        packets: list[CapturedPacket] = []
        for i, t in enumerate(every(T0, 600.0, 0.5)):
            packets.append(icmp(t))
            packets.append(udp(t + timedelta(milliseconds=100), port=5000 + i % 3))
            packets.append(arp(t + timedelta(milliseconds=200), f"10.98.1.{1 + i % 3}"))
        for i, t in enumerate(every(T0, 600.0, 0.25)):
            packets.append(syn(t + timedelta(milliseconds=300), port=(80, 443)[i % 2]))
        return sorted(packets, key=lambda p: p.captured_at)

    def test_no_episode_no_record_no_announcement(self, clean_db) -> None:
        p = Pipeline(clean_db)
        started = time.perf_counter()
        p.feed(self._ten_minutes())
        elapsed = time.perf_counter() - started
        assert p.emitted == []
        assert p.rows() == []
        assert p.bus.detections() == []
        assert elapsed < 10.0, f"{elapsed:.2f} s to analyse 10 min of low-rate traffic"


# ===========================================================================
# TEST H - low rate after a qualifying episode
# ===========================================================================
class TestH_LowRateAfterAnEpisode:
    def test_low_rate_does_not_extend_the_flood_and_a_new_flood_is_new(self, clean_db) -> None:
        flood_1 = every(T0, 10.0, 300.0)
        quiet = every(T0 + timedelta(seconds=11), 60.0, 1.5)
        flood_2 = every(T0 + timedelta(seconds=80), 10.0, 300.0)
        p = Pipeline(clean_db).feed(icmp(t) for t in flood_1 + quiet + flood_2)
        rows = p.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 2
        first, second = rows

        def naive(value):  # noqa: ANN001, ANN202
            return value.replace(tzinfo=None)

        # The rule's rate is a 5 s window average: for up to one window after
        # the last flood packet the window still holds >= 600 of them, so the
        # episode may update until then - and no later. The 60 s of 1.5 pps
        # that follow must not extend it.
        window = timedelta(seconds=DetectionThresholds().rate_window)
        assert naive(first.last_seen) <= naive(flood_1[-1]) + window
        assert float(first.observed_value) >= 290.0  # historical peak kept
        assert float(first.latest_value) >= 120.0  # a window rate, never 1.5 pps
        assert naive(second.first_seen) >= naive(quiet[-1]) - timedelta(seconds=5)


# ===========================================================================
# TEST I - repeated processing
# ===========================================================================
class TestI_RepeatedProcessing:
    def test_the_same_episode_starts_processed_again_create_nothing(self, clean_db) -> None:
        p = Pipeline(clean_db).feed(sweep(T0, 7.0) + sweep(T0 + timedelta(seconds=64), 7.0))
        before = [(r.id, float(r.observed_value), r.event_count)
                  for r in p.rows(RULE_HOST_SWEEP)]
        announced = len(p.bus.detections())
        for anomaly in p.opened(RULE_HOST_SWEEP):
            p.service._store_anomaly(anomaly)  # noqa: SLF001
        after = [(r.id, float(r.observed_value), r.event_count)
                 for r in p.rows(RULE_HOST_SWEEP)]
        assert after == before
        assert len(p.bus.detections()) == announced

    def test_reloading_the_alerts_list_changes_nothing(self, clean_db) -> None:
        p = Pipeline(clean_db).feed(sweep(T0, 7.0))
        repo = p.repo
        first = [(a.id, a.event_count, float(a.observed_value)) for a in repo.search_anomalies()]
        second = [(a.id, a.event_count, float(a.observed_value)) for a in repo.search_anomalies()]
        assert first == second and len(first) == 1


# ===========================================================================
# TEST J - decision, storage, query, statistics and display agree
# ===========================================================================
class TestJ_Consistency:
    def test_one_record_everywhere_with_matching_numbers(self, clean_db) -> None:
        from aethra_sec.ui.screens.alerts import (
            _episode_narrative,
            _format_pps,
            _measured_rate,
            _rate_unit,
        )

        repo = AlertRepository(clean_db)
        old = Pipeline(clean_db).feed(icmp(t, src="10.98.9.9")
                                      for t in every(T0 - timedelta(hours=1), 10.0, 200.0))
        historical = [r.id for r in old.rows(RULE_ICMP_FLOOD)]
        p = Pipeline(clean_db).feed(sweep(T0, 7.0))
        p.feed(icmp(t, src="10.98.3.3") for t in every(T0 + timedelta(minutes=5), 60.0, 1.5))

        assert [r.id for r in p.rows(RULE_ICMP_FLOOD)] == historical  # kept, none added
        listed = repo.search_anomalies(rule_id=RULE_HOST_SWEEP)
        assert len(listed) == 1
        row = listed[0]
        stats = {s["rule_id"]: s["episodes"]
                 for s in repo.aethra_episode_statistics(None, None, datetime.now(UTC))}
        assert stats[RULE_HOST_SWEEP] == 1
        assert stats[RULE_ICMP_FLOOD] == len(historical)

        assert _rate_unit(row) == "hosts"
        assert _measured_rate(row) == _format_pps(row.evidence["packets_per_second"])
        narrative = _episode_narrative(row)
        assert "threshold of 15 hosts over 10 s" in narrative
        assert "15 pps" not in narrative
        assert f"Peak measurement: {int(float(row.observed_value))} hosts" in narrative

    def test_a_failed_query_raises_instead_of_reading_as_zero(self) -> None:
        class _Down:
            def query(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
                raise RuntimeError("database unavailable")

        repo = AlertRepository.__new__(AlertRepository)
        repo.db = _Down()
        with pytest.raises(RuntimeError):
            repo.search_anomalies()

    def test_units_for_every_rule(self) -> None:
        from aethra_sec.ui.screens.alerts import _rate_unit

        unit = {r: _rate_unit(SimpleNamespace(rule_id=r)) for r in (
            RULE_ICMP_FLOOD, RULE_UDP_FLOOD, RULE_SYN_FLOOD, RULE_HTTP_FLOOD,
            RULE_PORT_SCAN, RULE_HOST_SWEEP)}
        assert unit == {RULE_ICMP_FLOOD: "pps", RULE_UDP_FLOOD: "pps",
                        RULE_SYN_FLOOD: "pps", RULE_HTTP_FLOOD: "req/s",
                        RULE_PORT_SCAN: "ports", RULE_HOST_SWEEP: "hosts"}


# ===========================================================================
# TEST K - bounded higher-rate input
# ===========================================================================
class TestK_HigherRateStability:
    def test_bounded_2000_pps_flood_is_one_high_record(self, clean_db) -> None:
        p = Pipeline(clean_db)
        started = time.perf_counter()
        p.feed(icmp(t) for t in every(T0, 10.0, 2000.0))  # 20,000 packets
        elapsed = time.perf_counter() - started
        rows = p.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 1
        assert str(rows[0].severity) == "HIGH"
        assert float(rows[0].observed_value) >= 1000.0
        assert 1 <= len(p.bus.detections()) <= 3  # opening + at most two escalations
        assert p.engine._tracked_keys() < 50  # noqa: SLF001
        assert elapsed < 60.0, f"{elapsed:.1f} s"

    def test_engine_state_is_released_after_episodes_end(self) -> None:
        p = Pipeline()
        for k in range(20):
            p.feed(sweep(T0 + timedelta(seconds=64 * k), 2.0, src=f"10.98.5.{k + 1}",
                         prefix=f"10.{k}.1."))
        p.engine._prune(  # noqa: SLF001
            (T0 + timedelta(seconds=64 * 20 + 300)).timestamp(), DetectionThresholds())
        assert p.engine._extent_reported == {}  # noqa: SLF001


# ===========================================================================
# TEST L - repeated attacks
# ===========================================================================
class TestL_RepeatedAttacks:
    def test_two_sweeps_64_s_apart_are_two_episodes(self, clean_db) -> None:
        p = Pipeline(clean_db).feed(sweep(T0, 7.0) + sweep(T0 + timedelta(seconds=64), 7.0))
        rows = p.rows(RULE_HOST_SWEEP)
        assert len(rows) == 2
        assert all(float(r.observed_value) >= 200 for r in rows)
        assert len(p.opened(RULE_HOST_SWEEP)) == 2

    def test_one_continuous_sweep_is_one_episode(self, clean_db) -> None:
        # Two subnets back to back with no pause: one running sweep.
        packets = sweep(T0, 7.0) + sweep(T0 + timedelta(seconds=7.1), 7.0, prefix="10.98.2.")
        p = Pipeline(clean_db).feed(packets)
        assert len(p.rows(RULE_HOST_SWEEP)) == 1

    def test_two_floods_30_s_apart_are_two_episodes(self, clean_db) -> None:
        stamps = every(T0, 10.0, 300.0) + every(T0 + timedelta(seconds=40), 10.0, 300.0)
        p = Pipeline(clean_db).feed(icmp(t) for t in stamps)
        assert len(p.rows(RULE_ICMP_FLOOD)) == 2
