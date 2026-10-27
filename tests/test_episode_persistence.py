"""What folding preserves, and what it must never invent.

These run against the dedicated test database through the ``clean_db``
fixture, so no laboratory record is read or written. Every timestamp is a
fixture written by the test.

The defect under test: a repeat alert folded into an existing row incremented
the count and moved ``received_at`` - an ingestion time - while discarding the
repeat's own Snort timestamp. The row could then say how often something fired
and not when it last fired.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aethra_sec.analytics.episodes import EpisodeStatus
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import Severity

#: Timezone-aware, because that is what the application stores and reads
#: back - a naive fixture would compare unequal to its own stored value.
BASE = datetime(2026, 10, 13, 9, 0, 0, tzinfo=UTC)


def _alert(**overrides) -> SnortAlert:
    """A plainly identifiable test alert."""
    fields = {
        "alert_time": BASE,
        "received_at": BASE,
        "signature_id": 9_000_001,
        "generator_id": 1,
        "message": "TEST FIXTURE - not a real detection",
        "severity": Severity.MEDIUM,
        "protocol": "ICMP",
        "src_ip": "10.99.0.10",
        "dst_ip": "10.99.0.20",
        "dedup_key": "TEST|RULE|10.99.0.10|10.99.0.20",
        "raw_alert": "TEST FIXTURE LINE 1",
        "created_at": BASE,
    }
    fields.update(overrides)
    return SnortAlert(**fields)


class TestFoldingPreservesTheEpisode:
    def test_a_first_alert_records_its_own_time_as_last_observed(
        self, clean_db
    ) -> None:
        """One sighting: first and last are the same instant, not unknown."""
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        stored = repo.get_alert(alert_id)
        assert stored is not None
        assert stored.last_alert_time == BASE
        assert stored.duplicate_count == 1
        episode = stored.episode(inactivity_seconds=120, now=BASE)
        assert episode.duration == timedelta(0)
        assert episode.duration_text == "single observation"

    def test_a_repeat_advances_last_observed_and_the_count(
        self, clean_db
    ) -> None:
        """The behaviour that was missing entirely."""
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        later = BASE + timedelta(minutes=7)
        repo.increment_duplicate(alert_id, later + timedelta(seconds=3), later)

        stored = repo.get_alert(alert_id)
        assert stored is not None
        assert stored.duplicate_count == 2
        assert stored.alert_time == BASE, "the first sighting must not move"
        assert stored.last_alert_time == later
        episode = stored.episode(
            inactivity_seconds=120, now=later + timedelta(seconds=30)
        )
        assert episode.duration == timedelta(minutes=7)
        assert episode.duration_text == "7 minutes"
        assert episode.status is EpisodeStatus.ONGOING

    def test_many_repeats_build_one_episode(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        for minute in range(1, 13):
            stamp = BASE + timedelta(minutes=minute)
            repo.increment_duplicate(alert_id, stamp, stamp)

        stored = repo.get_alert(alert_id)
        assert stored is not None
        assert stored.duplicate_count == 13
        assert stored.last_alert_time == BASE + timedelta(minutes=12)
        episode = stored.episode(
            inactivity_seconds=120, now=BASE + timedelta(minutes=12, seconds=5)
        )
        assert episode.duration_text == "12 minutes"
        assert episode.occurrences == 13

    def test_last_observed_only_moves_forwards(self, clean_db) -> None:
        """Re-reading an older alert file must not rewind the episode.

        A Snort alert file replayed after a restart carries events that are
        minutes old. Folding one of those must not drag the last-observed
        time backwards and shorten an episode that really did continue.
        """
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        newest = BASE + timedelta(minutes=10)
        repo.increment_duplicate(alert_id, newest, newest)
        stale = BASE + timedelta(minutes=2)
        repo.increment_duplicate(alert_id, newest + timedelta(seconds=1), stale)

        stored = repo.get_alert(alert_id)
        assert stored is not None
        assert stored.last_alert_time == newest
        assert stored.duplicate_count == 3, "the occurrence still counts"

    def test_a_repeat_without_a_timestamp_leaves_last_observed_alone(
        self, clean_db
    ) -> None:
        """A sensor that sends no time must not blank what is already known."""
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        known = BASE + timedelta(minutes=4)
        repo.increment_duplicate(alert_id, known, known)
        repo.increment_duplicate(alert_id, known + timedelta(minutes=1), None)

        stored = repo.get_alert(alert_id)
        assert stored is not None
        assert stored.last_alert_time == known
        assert stored.duplicate_count == 3


class TestEpisodesAreNotMergedAcrossUnrelatedTraffic:
    def test_a_different_source_is_a_different_record(self, clean_db) -> None:
        """Folding is keyed on the dedup key, not on the signature alone."""
        repo = AlertRepository(clean_db)
        first = repo.insert_alert(_alert())
        second = repo.insert_alert(
            _alert(
                src_ip="10.99.0.77",
                dedup_key="TEST|RULE|10.99.0.77|10.99.0.20",
                raw_alert="TEST FIXTURE LINE 2",
            )
        )
        assert first != second
        repo.increment_duplicate(
            first, BASE + timedelta(minutes=1), BASE + timedelta(minutes=1)
        )
        a = repo.get_alert(first)
        b = repo.get_alert(second)
        assert a is not None and b is not None
        assert a.duplicate_count == 2
        assert b.duplicate_count == 1, "an unrelated source must not be folded"
        assert b.last_alert_time == BASE

    def test_find_duplicate_is_bounded_by_the_window(self, clean_db) -> None:
        """A repeat outside the window starts a new episode rather than
        extending a stale one."""
        repo = AlertRepository(clean_db)
        repo.insert_alert(_alert(received_at=BASE))
        inside = repo.find_duplicate(
            "TEST|RULE|10.99.0.10|10.99.0.20", BASE - timedelta(seconds=120)
        )
        assert inside is not None
        outside = repo.find_duplicate(
            "TEST|RULE|10.99.0.10|10.99.0.20", BASE + timedelta(seconds=120)
        )
        assert outside is None


class TestRestartsDoNotFabricate:
    def test_reading_a_stored_row_twice_gives_the_same_episode(
        self, clean_db
    ) -> None:
        """Status is computed on read; the stored timestamps never move."""
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        last = BASE + timedelta(minutes=5)
        repo.increment_duplicate(alert_id, last, last)

        first_read = repo.get_alert(alert_id)
        second_read = repo.get_alert(alert_id)
        assert first_read is not None and second_read is not None
        assert first_read.alert_time == second_read.alert_time == BASE
        assert first_read.last_alert_time == second_read.last_alert_time == last
        assert first_read.duplicate_count == second_read.duplicate_count == 2

    def test_the_same_row_is_ongoing_then_ended_as_time_passes(
        self, clean_db
    ) -> None:
        """Nothing is stored as ONGOING; it is judged against the clock.

        The same unchanged row reads ONGOING shortly after its last
        observation and ENDED once the timeout has passed, which is what
        stops a surviving row from claiming an attack is still running.
        """
        repo = AlertRepository(clean_db)
        alert_id = repo.insert_alert(_alert())
        last = BASE + timedelta(minutes=5)
        repo.increment_duplicate(alert_id, last, last)
        stored = repo.get_alert(alert_id)
        assert stored is not None

        assert stored.episode(
            inactivity_seconds=120, now=last + timedelta(seconds=30)
        ).status is EpisodeStatus.ONGOING
        assert stored.episode(
            inactivity_seconds=120, now=last + timedelta(hours=3)
        ).status is EpisodeStatus.ENDED
