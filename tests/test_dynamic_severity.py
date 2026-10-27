"""Severity follows the attack: current value, peak, and transition history.

The defect under test: ``severity`` was written once when an anomaly was
inserted and no code path ever updated it, so a flood detected at 500 pps
stayed MEDIUM however far it escalated.

Every rate here is a fixture written by the test. Nothing reads the laboratory
database and no value is presented as a real network observation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aethra_sec.analytics.anomaly_rules import (
    FLOOD_BAND_HIGH_FLOOR,
    FLOOD_BAND_MEDIUM_FLOOR,
    FLOOD_RULES,
    flood_band,
    flood_severity,
)
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import TrafficAnomaly

BASE = datetime(2026, 10, 13, 14, 0, 0, tzinfo=UTC)


def _anomaly(rate: float, **overrides) -> TrafficAnomaly:
    """A plainly identifiable flood detection at a given measured rate."""
    severity, _band = flood_severity(rate)
    fields = {
        "rule_id": "RULE-TCP-SYN-RATE",
        "category": ThreatCategory.UNCLASSIFIED,
        "title": "TEST FIXTURE - not a real detection",
        "severity": severity,
        "src_ip": "10.98.0.10",
        "dst_ip": "10.98.0.20",
        "dst_port": None,
        "protocol": "TCP",
        "observed_value": rate,
        "threshold_value": 200.0,
        "window_seconds": 5,
        "detected_at": BASE,
        "first_seen": BASE,
        "last_seen": BASE,
        "source": EvidenceSource.PYSHARK,
        "created_at": BASE,
    }
    fields.update(overrides)
    return TrafficAnomaly(**fields)


class TestTheRequiredBoundaries:
    """0-499 LOW, 500-999 MEDIUM, 1,000 and above HIGH."""

    @pytest.mark.parametrize(
        ("pps", "expected"),
        [
            (0, Severity.LOW),
            (499, Severity.LOW),
            (499.9, Severity.LOW),
            (500, Severity.MEDIUM),
            (750, Severity.MEDIUM),
            (999, Severity.MEDIUM),
            (999.9, Severity.MEDIUM),
            (1000, Severity.HIGH),
            (1200, Severity.HIGH),
            (50_000, Severity.HIGH),
        ],
    )
    def test_each_boundary(self, pps: float, expected: Severity) -> None:
        assert flood_severity(float(pps))[0] is expected

    def test_one_thousand_is_high_not_medium(self) -> None:
        """The boundary this revision exists to move."""
        assert flood_severity(1000.0)[0] is Severity.HIGH
        assert flood_severity(999.999)[0] is Severity.MEDIUM

    def test_both_floors_are_inclusive(self) -> None:
        assert (FLOOD_BAND_MEDIUM_FLOOR, FLOOD_BAND_HIGH_FLOOR) == (500.0, 1000.0)
        assert flood_severity(FLOOD_BAND_MEDIUM_FLOOR)[0] is Severity.MEDIUM
        assert flood_severity(FLOOD_BAND_HIGH_FLOOR)[0] is Severity.HIGH

    def test_the_printed_ranges_match_the_comparison(self) -> None:
        """A displayed range that disagrees with the applied one is a lie."""
        assert flood_band(Severity.HIGH).min_pps == 1000
        assert flood_band(Severity.HIGH).max_pps is None
        assert flood_band(Severity.MEDIUM).min_pps == 500
        assert flood_band(Severity.MEDIUM).max_pps == 999
        assert flood_band(Severity.LOW).max_pps == 499


class TestTheModelSeparatesCurrentFromPeak:
    def test_peak_is_reported_when_the_rate_falls_back(self) -> None:
        anomaly = _anomaly(
            800.0, severity=Severity.MEDIUM, peak_severity=Severity.HIGH,
            latest_value=800.0,
        )
        assert anomaly.current_severity is Severity.MEDIUM
        assert anomaly.highest_severity is Severity.HIGH
        assert anomaly.escalated

    def test_a_missing_peak_falls_back_to_the_current_value(self) -> None:
        """A floor taken from the row, not a guess about an escalation."""
        anomaly = _anomaly(600.0, peak_severity=None)
        assert anomaly.highest_severity is Severity.MEDIUM
        assert not anomaly.escalated

    def test_the_peak_is_never_reported_below_the_current_value(self) -> None:
        anomaly = _anomaly(
            1200.0, severity=Severity.HIGH, peak_severity=Severity.LOW
        )
        assert anomaly.highest_severity is Severity.HIGH

    def test_latest_rate_never_falls_back_to_the_peak(self) -> None:
        """Showing a peak as the current rate would overstate the present."""
        anomaly = _anomaly(1200.0, latest_value=None)
        assert anomaly.observed_value == 1200.0
        assert anomaly.latest_rate is None


class TestOneEscalatingEpisode:
    """The sequence from the brief, against the real repository."""

    def test_severity_is_raised_while_the_live_rate_still_tracks(
        self, clean_db
    ) -> None:
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(500.0))

        stored = repo.get_anomaly(anomaly_id)
        assert stored is not None
        assert stored.severity is Severity.MEDIUM
        assert stored.highest_severity is Severity.MEDIUM

        seen: list[tuple[float, Severity, Severity]] = []
        previous = stored.severity
        for offset, rate in enumerate(
            [750.0, 1000.0, 1200.0, 800.0], start=1
        ):
            current, _band = flood_severity(rate)
            at = BASE + timedelta(seconds=10 * offset)
            repo.update_anomaly_occurrence(
                anomaly_id, last_seen=at, observed_value=rate,
                severity=current, measured_at=at,
            )
            if current != previous:
                repo.record_severity_transition(
                    anomaly_id, occurred_at=at, previous=previous,
                    new=current, observed_value=rate, window_seconds=5,
                    measured_at=at,
                )
            previous = current
            row = repo.get_anomaly(anomaly_id)
            assert row is not None
            seen.append((rate, row.severity, row.highest_severity))

        # The last sample, 800 pps, classifies MEDIUM on its own - but the
        # episode has already measured 1,200 pps, and an attack's severity is
        # the worst rate it validly reached. The falling rate is not lost: it
        # is in ``latest_rate`` and shown in the Alerts screen's Now column.
        assert seen == [
            (750.0, Severity.MEDIUM, Severity.MEDIUM),
            (1000.0, Severity.HIGH, Severity.HIGH),
            (1200.0, Severity.HIGH, Severity.HIGH),
            (800.0, Severity.HIGH, Severity.HIGH),
        ]

        final = repo.get_anomaly(anomaly_id)
        assert final is not None
        assert final.severity is Severity.HIGH, (
            "severity must state the worst rate measured, not the last one"
        )
        assert final.highest_severity is Severity.HIGH, "the peak holds"
        assert final.latest_rate == 800.0, (
            "the live rate must still be recorded, or the falling rate is lost"
        )
        assert final.observed_value == 1200.0, "observed_value stays the peak"
        assert final.event_count == 5

    def test_the_current_band_is_still_derivable_from_the_live_rate(
        self, clean_db
    ) -> None:
        """The dynamic measurement survives the monotonic severity.

        This is what the Alerts screen's Now column reads, so an operator can
        still see that a HIGH episode has calmed down.
        """
        from aethra_sec.ui.screens.alerts import _current_band

        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(1733.2))
        at = BASE + timedelta(seconds=5)
        repo.update_anomaly_occurrence(
            anomaly_id, last_seen=at, observed_value=497.2,
            severity=Severity.LOW, measured_at=at,
        )
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.HIGH, "the attack reached HIGH"
        assert row.latest_rate == 497.2
        assert _current_band(row) == str(Severity.LOW), (
            "the Now column must report the live band"
        )

    def test_only_real_changes_are_logged(self, clean_db) -> None:
        """A steady flood writes no transition rows."""
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(500.0))
        previous = Severity.MEDIUM
        for offset, rate in enumerate(
            [750.0, 1000.0, 1200.0, 800.0], start=1
        ):
            current, _b = flood_severity(rate)
            at = BASE + timedelta(seconds=10 * offset)
            repo.update_anomaly_occurrence(
                anomaly_id, last_seen=at, observed_value=rate,
                severity=current, measured_at=at,
            )
            if current != previous:
                repo.record_severity_transition(
                    anomaly_id, occurred_at=at, previous=previous,
                    new=current, observed_value=rate, window_seconds=5,
                    measured_at=at,
                )
            previous = current

        history = repo.severity_transitions(anomaly_id)
        assert len(history) == 2, "750 and 1,200 changed nothing"
        assert history[0]["previous_severity"] == "MEDIUM"
        assert history[0]["new_severity"] == "HIGH"
        assert float(history[0]["observed_value"]) == 1000.0
        assert history[1]["previous_severity"] == "HIGH"
        assert history[1]["new_severity"] == "MEDIUM"
        assert float(history[1]["observed_value"]) == 800.0
        assert history[0]["occurred_at"] < history[1]["occurred_at"]

    def test_a_steady_flood_logs_nothing(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(1200.0))
        for offset in range(1, 40):
            at = BASE + timedelta(seconds=offset)
            repo.update_anomaly_occurrence(
                anomaly_id, last_seen=at, observed_value=1210.0,
                severity=Severity.HIGH, measured_at=at,
            )
        assert repo.severity_transitions(anomaly_id) == []
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.event_count == 40
        assert row.severity is Severity.HIGH


class TestTheFoldIsSafe:
    def test_neither_severity_nor_peak_is_lowered_by_a_later_write(
        self, clean_db
    ) -> None:
        """A slower sample must not un-report what the attack reached.

        This is the fix for the reported bug, at the level of the statement
        that writes it: the episode measured 1,200 pps, so 100 pps arriving
        afterwards records the new rate without rewriting the severity.
        """
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(1200.0))
        at = BASE + timedelta(seconds=5)
        repo.update_anomaly_occurrence(
            anomaly_id, last_seen=at, observed_value=100.0,
            severity=Severity.LOW, measured_at=at,
        )
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.HIGH, "severity was lowered"
        assert row.latest_rate == 100.0, "the new rate was not recorded"
        assert row.highest_severity is Severity.HIGH, "the peak is kept"
        assert row.observed_value == 1200.0

    def test_omitting_severity_leaves_the_stored_value_alone(
        self, clean_db
    ) -> None:
        """Correct for a rule whose severity does not come from a rate."""
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(
            _anomaly(300.0, rule_id="RULE-PORT-SCAN",
                     severity=Severity.MEDIUM)
        )
        at = BASE + timedelta(seconds=5)
        repo.update_anomaly_occurrence(
            anomaly_id, last_seen=at, observed_value=12.0, measured_at=at,
        )
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.MEDIUM, "unchanged"
        assert row.event_count == 2, "the observation still counts"
        assert row.latest_rate == 12.0

    def test_only_flood_rules_are_rate_classified(self) -> None:
        """Port scans and host sweeps count ports and hosts, not packets."""
        assert "RULE-PORT-SCAN" not in FLOOD_RULES
        assert "RULE-HOST-SWEEP" not in FLOOD_RULES
        assert FLOOD_RULES == {
            "RULE-ICMP-RATE", "RULE-UDP-RATE",
            "RULE-TCP-SYN-RATE", "RULE-HTTP-RATE",
        }


class TestUnrelatedAttacksStayApart:
    def test_a_different_source_is_a_separate_episode(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        first = repo.insert_anomaly(_anomaly(500.0))
        second = repo.insert_anomaly(_anomaly(500.0, src_ip="10.98.0.99"))
        assert first != second
        at = BASE + timedelta(seconds=5)
        repo.update_anomaly_occurrence(
            first, last_seen=at, observed_value=1200.0,
            severity=Severity.HIGH, measured_at=at,
        )
        a, b = repo.get_anomaly(first), repo.get_anomaly(second)
        assert a is not None and b is not None
        assert a.severity is Severity.HIGH
        assert b.severity is Severity.MEDIUM, "the other source is untouched"
        assert b.event_count == 1

    def test_the_correlation_key_separates_sources(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        repo.insert_anomaly(_anomaly(500.0))
        since = BASE - timedelta(seconds=120)
        assert repo.recent_anomaly(
            ("RULE-TCP-SYN-RATE", "10.98.0.10", "10.98.0.20", None), since
        ) is not None
        assert repo.recent_anomaly(
            ("RULE-TCP-SYN-RATE", "10.98.0.99", "10.98.0.20", None), since
        ) is None
        assert repo.recent_anomaly(
            ("RULE-UDP-RATE", "10.98.0.10", "10.98.0.20", None), since
        ) is None


class TestHistoryIsNotInvented:
    def test_a_fresh_record_has_no_transitions(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(1200.0))
        assert repo.severity_transitions(anomaly_id) == []

    def test_a_first_sighting_records_its_own_rate_as_latest(
        self, clean_db
    ) -> None:
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(650.0))
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.latest_rate == 650.0
        assert row.observed_value == 650.0
        assert row.highest_severity is Severity.MEDIUM

    def test_reading_twice_gives_the_same_values(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(500.0))
        at = BASE + timedelta(seconds=5)
        repo.update_anomaly_occurrence(
            anomaly_id, last_seen=at, observed_value=1200.0,
            severity=Severity.HIGH, measured_at=at,
        )
        one, two = repo.get_anomaly(anomaly_id), repo.get_anomaly(anomaly_id)
        assert one is not None and two is not None
        assert one.severity == two.severity
        assert one.highest_severity == two.highest_severity
        assert one.latest_rate == two.latest_rate
        assert one.first_seen == two.first_seen
