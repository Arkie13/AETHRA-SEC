"""Observed attack episodes: duration, status, and what folding preserves.

These cover the defect the episode work was done for: a detection row that
folded hundreds of repeats could say how often something fired and when it was
first seen, but not when it last fired, so a recurring attack was
indistinguishable from a single event.

Every timestamp here is a fixture written by the test. Nothing reads the
laboratory database and nothing asserts anything about real traffic.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aethra_sec.analytics.episodes import (
    DEFAULT_INACTIVITY_SECONDS,
    Episode,
    EpisodeStatus,
    describe,
    episode_status,
    format_duration,
    observed_duration,
)
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.threat import TrafficAnomaly

NOW = datetime(2026, 10, 13, 12, 0, 0)


class TestObservedDuration:
    """Duration is the span between two observations, or nothing."""

    def test_the_span_between_two_observations(self) -> None:
        span = observed_duration(NOW - timedelta(minutes=12), NOW)
        assert span == timedelta(minutes=12)

    def test_a_single_observation_spans_no_time(self) -> None:
        assert observed_duration(NOW, NOW) == timedelta(0)

    def test_a_missing_timestamp_yields_no_duration(self) -> None:
        """Not zero. Zero is a measurement; this is the absence of one."""
        assert observed_duration(None, NOW) is None
        assert observed_duration(NOW, None) is None
        assert observed_duration(None, None) is None

    def test_a_reversed_pair_yields_no_duration(self) -> None:
        """Last before first means the clocks disagree.

        Returning None keeps the clock problem visible. Clamping to zero would
        hide it behind a value that looks like a real measurement.
        """
        assert observed_duration(NOW, NOW - timedelta(seconds=5)) is None


class TestDurationText:
    """The wording an operator reads."""

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (0, "single observation"),
            (1, "1 second"),
            (45, "45 seconds"),
            (60, "1 minute"),
            (750, "12 minutes, 30 seconds"),
            (3900, "1 hour, 5 minutes"),
            (7200, "2 hours"),
            (90000, "1 day, 1 hour"),
        ],
    )
    def test_readable_spans(self, seconds: int, expected: str) -> None:
        assert format_duration(timedelta(seconds=seconds)) == expected

    def test_no_measurement_is_a_dash_not_a_zero(self) -> None:
        assert format_duration(None) == "—"


class TestEpisodeStatus:
    """Ongoing, ended, or honestly unknown."""

    def test_a_recent_observation_is_ongoing(self) -> None:
        assert episode_status(
            NOW - timedelta(minutes=5), NOW - timedelta(seconds=30),
            inactivity_seconds=120, now=NOW,
        ) is EpisodeStatus.ONGOING

    def test_the_timeout_boundary_belongs_to_ongoing(self) -> None:
        """Exactly at the timeout is still inside it."""
        assert episode_status(
            NOW - timedelta(minutes=5), NOW - timedelta(seconds=120),
            inactivity_seconds=120, now=NOW,
        ) is EpisodeStatus.ONGOING
        assert episode_status(
            NOW - timedelta(minutes=5), NOW - timedelta(seconds=121),
            inactivity_seconds=120, now=NOW,
        ) is EpisodeStatus.ENDED

    def test_the_timeout_is_configurable(self) -> None:
        last = NOW - timedelta(seconds=300)
        assert episode_status(
            NOW - timedelta(minutes=10), last,
            inactivity_seconds=120, now=NOW,
        ) is EpisodeStatus.ENDED
        assert episode_status(
            NOW - timedelta(minutes=10), last,
            inactivity_seconds=600, now=NOW,
        ) is EpisodeStatus.ONGOING

    def test_no_last_observation_is_unknown(self) -> None:
        """The commonest real case: repeats counted but never timestamped."""
        assert episode_status(
            NOW - timedelta(hours=1), None, now=NOW,
        ) is EpisodeStatus.UNKNOWN

    def test_a_reversed_pair_is_unknown(self) -> None:
        assert episode_status(
            NOW, NOW - timedelta(minutes=5), now=NOW,
        ) is EpisodeStatus.UNKNOWN

    def test_a_future_observation_is_unknown(self) -> None:
        assert episode_status(
            NOW - timedelta(minutes=5), NOW + timedelta(minutes=5), now=NOW,
        ) is EpisodeStatus.UNKNOWN

    def test_ended_does_not_claim_the_attack_stopped(self) -> None:
        assert "not proof" in EpisodeStatus.ENDED.explanation


class TestASingleAlertImpliesNothing:
    """The defect this work exists to prevent."""

    def test_one_observation_is_not_an_hour_long_attack(self) -> None:
        """An alert raised an hour ago, seen once, is not a one-hour attack.

        The record has existed for an hour. The activity was observed once.
        The duration is the span of the observations, not the age of the row.
        """
        alert = SnortAlert(
            alert_time=NOW - timedelta(hours=1),
            last_alert_time=NOW - timedelta(hours=1),
            duplicate_count=1,
        )
        episode = alert.episode(inactivity_seconds=120, now=NOW)
        assert episode.duration == timedelta(0)
        assert episode.duration_text == "single observation"
        assert episode.is_single_observation
        assert episode.status is EpisodeStatus.ENDED

    def test_an_old_row_is_not_ongoing_merely_by_existing(self) -> None:
        alert = SnortAlert(
            alert_time=NOW - timedelta(days=30),
            last_alert_time=NOW - timedelta(days=30),
            duplicate_count=5000,
        )
        assert alert.episode(
            inactivity_seconds=120, now=NOW
        ).status is EpisodeStatus.ENDED

    def test_a_folded_row_without_a_last_timestamp_is_unknown(self) -> None:
        """Rows written before the column existed say so, rather than guess."""
        alert = SnortAlert(
            alert_time=NOW - timedelta(minutes=20),
            last_alert_time=None,
            duplicate_count=145_451,
        )
        episode = alert.episode(inactivity_seconds=120, now=NOW)
        assert episode.status is EpisodeStatus.UNKNOWN
        assert episode.duration is None
        assert episode.duration_text == "—"
        assert episode.occurrences == 145_451


class TestARecurringAttackReadsAsOne:
    """What an operator should be able to see."""

    def test_a_twelve_minute_episode_reports_twelve_minutes(self) -> None:
        alert = SnortAlert(
            alert_time=NOW - timedelta(minutes=12),
            last_alert_time=NOW - timedelta(seconds=20),
            duplicate_count=842,
        )
        episode = alert.episode(inactivity_seconds=120, now=NOW)
        assert episode.duration_text == "11 minutes, 40 seconds"
        assert episode.status is EpisodeStatus.ONGOING
        assert episode.occurrences == 842
        assert not episode.is_single_observation

    def test_an_anomaly_episode_uses_its_own_stored_span(self) -> None:
        anomaly = TrafficAnomaly(
            rule_id="RULE-ICMP-RATE",
            first_seen=NOW - timedelta(minutes=8),
            last_seen=NOW - timedelta(minutes=1),
            event_count=96,
        )
        episode = anomaly.episode(inactivity_seconds=120, now=NOW)
        assert episode.duration == timedelta(minutes=7)
        assert episode.status is EpisodeStatus.ONGOING
        assert episode.occurrences == 96

    def test_detected_at_stands_in_when_first_seen_is_absent(self) -> None:
        anomaly = TrafficAnomaly(
            rule_id="RULE-HOST-SWEEP",
            first_seen=None,
            detected_at=NOW - timedelta(minutes=3),
            last_seen=NOW - timedelta(minutes=2),
            event_count=4,
        )
        assert anomaly.episode(
            inactivity_seconds=120, now=NOW
        ).duration == timedelta(minutes=1)


class TestDescribe:
    """The summary the interface is built from."""

    def test_it_reports_what_it_was_given(self) -> None:
        episode = describe(
            NOW - timedelta(minutes=2), NOW - timedelta(seconds=10), 7,
            inactivity_seconds=120, now=NOW,
        )
        assert isinstance(episode, Episode)
        assert episode.occurrences == 7
        assert episode.duration == timedelta(seconds=110)
        assert episode.status is EpisodeStatus.ONGOING

    def test_an_occurrence_count_is_never_below_one(self) -> None:
        """A stored record stands for at least the observation that made it."""
        assert describe(NOW, NOW, 0, now=NOW).occurrences == 1

    def test_the_default_timeout_matches_the_suppression_window(self) -> None:
        """Both describe the same thing: how long a repeat still belongs."""
        from aethra_sec.config.defaults import DETECTION_SETTINGS

        suppression = next(
            s for s in DETECTION_SETTINGS
            if s.key == "detection.suppression_window_seconds"
        )
        assert DEFAULT_INACTIVITY_SECONDS == suppression.default


class TestDurationIsNotDetectionTime:
    """Two different measurements that must not be conflated."""

    def test_the_module_says_so(self) -> None:
        import aethra_sec.analytics.episodes as module

        doc = (module.__doc__ or "")
        assert "3.9.2" in doc, "the distinction must be written down"
        assert "not" in doc.lower()

    def test_nothing_here_computes_detection_time(self) -> None:
        """Detection time needs an attack-initiation timestamp.

        This module never receives one, so it must not expose anything that
        looks like it has produced one.
        """
        import aethra_sec.analytics.episodes as module

        exported = {n.lower() for n in dir(module) if not n.startswith("_")}
        assert not any("detection_time" in n for n in exported)
        assert not any("latency" in n for n in exported)
