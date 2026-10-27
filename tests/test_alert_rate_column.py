"""The Alerts Rate column shows packets per second for every attack.

Flood rules that store their own pps show it; every other detection - HTTP
flood, port scan, host sweep, Snort alert - shows the pps its source sent,
measured one-directional from captured traffic. Never a host or port count,
never an invented figure. Every packet count here is a stub.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    RULE_HTTP_FLOOD,
    RULE_PORT_SCAN,
    RULE_SYN_FLOOD,
)
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.ui.screens.alerts import (
    ORIGIN_AETHRA,
    ORIGIN_SNORT,
    _format_pps,
    _measure_rates,
    _measured_rate,
)

NOW = datetime(2026, 10, 14, 12, 0, 0)


class _StubDb:
    def __init__(self, count: int) -> None:
        self.count = count
        self.sql = ""
        self.params: tuple = ()

    def query_value(self, sql, params=(), default=0):  # noqa: ANN001
        self.sql, self.params = sql, params
        return self.count


def _det(rule: str, observed: float | None = None, latest: float | None = None,
         **extra):
    return SimpleNamespace(rule_id=rule, observed_value=observed,
                           latest_value=latest, **extra)


def test_a_flood_shows_its_stored_pps() -> None:
    assert _measured_rate(_det(RULE_SYN_FLOOD, 205.8, 205.8)) == "205.8"


def test_a_flood_shows_one_number_the_peak_never_a_slash() -> None:
    # "948.2 / 943.0" read as a division; the peak alone is shown.
    shown = _measured_rate(_det(RULE_SYN_FLOOD, 948.2, 943.0))
    assert shown == "948.2"
    assert "/" not in shown


def test_a_floods_stored_rate_is_not_overridden_by_a_measurement() -> None:
    assert _measured_rate(_det(RULE_SYN_FLOOD, 205.8, 205.8), 90.0) == "205.8"


def test_a_host_sweep_shows_pps_not_hosts() -> None:
    sweep = _det(RULE_HOST_SWEEP, 15.0)
    assert _measured_rate(sweep, 1.5) == "1.5"
    assert "hosts" not in _measured_rate(sweep, 1.5)


def test_a_port_scan_shows_pps_not_ports() -> None:
    assert _measured_rate(_det(RULE_PORT_SCAN, 20.0), 3.5) == "3.5"


def test_an_http_flood_shows_measured_pps_not_requests() -> None:
    assert _measured_rate(_det(RULE_HTTP_FLOOD, 65.6, 65.6), 130.2) == "130.2"


def test_nothing_measured_shows_a_dash_not_zero() -> None:
    assert _measured_rate(_det(RULE_HOST_SWEEP, 15.0), None) == "-"
    assert _format_pps(0) == "-"
    assert _format_pps(None) == "-"


def test_measured_rate_for_counts_the_source_only() -> None:
    db = _StubDb(count=35)
    rate = TrafficRepository(db).measured_rate_for(
        "10.0.0.1", NOW, NOW + timedelta(seconds=10), dst_ip="10.0.0.2"
    )
    assert rate == 3.5
    assert "src_ip = %s" in db.sql and db.params[2] == "10.0.0.1"


def test_measured_rate_for_rejects_empty_window_or_source() -> None:
    repo = TrafficRepository(_StubDb(count=100))
    assert repo.measured_rate_for("", NOW, NOW + timedelta(seconds=5)) is None
    assert repo.measured_rate_for("10.0.0.1", NOW, NOW) is None


def test_measure_rates_skips_stored_floods_and_covers_snort() -> None:
    sweep = _det(RULE_HOST_SWEEP, 15.0, id=1, src_ip="10.0.0.9", dst_ip="",
                 window_seconds=10, last_seen=NOW)
    flood = _det(RULE_SYN_FLOOD, 205.8, id=2, src_ip="10.0.0.9",
                 dst_ip="10.0.0.1", window_seconds=5, last_seen=NOW)
    snort = SimpleNamespace(id=7, src_ip="10.0.0.28", dst_ip="10.0.0.1",
                            effective_time=NOW)

    class _Dash:
        calls = 0

        def measured_source_rate(self, *a, **k):  # noqa: ANN002, ANN003
            _Dash.calls += 1
            return 0.2

    rates = _measure_rates(_Dash(), [snort], [sweep, flood])
    assert rates == {(ORIGIN_AETHRA, 1): 0.2, (ORIGIN_SNORT, 7): 0.2}
    assert _Dash.calls == 2  # the flood was not measured


def test_a_graded_scan_shows_the_pps_it_was_graded_on() -> None:
    # The recorded rate wins over any later traffic measurement, so the Rate
    # column and the severity graded from it can never disagree.
    scan = _det(RULE_PORT_SCAN, 20.0,
                evidence={"packets_per_second": 812.4,
                          "severity_basis": "pps legend (§3.9.8)"})
    assert _measured_rate(scan, 3.5) == "812.4"


def test_measure_rates_skips_rows_that_carry_their_own_pps() -> None:
    graded = _det(RULE_HOST_SWEEP, 15.0, id=3, src_ip="10.0.0.9", dst_ip="",
                  window_seconds=10, last_seen=NOW,
                  evidence={"packets_per_second": 1.5})
    snort = SimpleNamespace(id=8, src_ip="10.0.0.28", dst_ip="10.0.0.1",
                            effective_time=NOW, peak_pps=389.6)

    class _Dash:
        def measured_source_rate(self, *a, **k):  # noqa: ANN002, ANN003
            raise AssertionError("should not be measured")

    assert _measure_rates(_Dash(), [snort], [graded]) == {}
