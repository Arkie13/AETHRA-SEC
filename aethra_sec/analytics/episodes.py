"""Observed attack episodes: how long activity was seen, and whether it is over.

A detection row answers "this fired". An operator watching a flood wants a
different question answered: has this been going on for twelve minutes, or did
it happen once? That needs three things the detection itself does not carry -
the span between the first and last observation, a readable form of that span,
and an honest answer to "is it still happening?".

What an observed duration is, and is not
----------------------------------------
    Observed Duration = Last Observed Timestamp - First Observed Timestamp

It is the interval over which matching activity was *observed*. It does not
assert that malicious traffic was continuously present across that interval,
and a gap in observations is not evidence that the attack stopped - it is
evidence that nothing matching was recorded. A single observation has a
duration of zero, which is the truth: one sighting spans no time. It must
never be presented as an attack that ran for as long as the record has
existed.

This is a different measurement from detection time, which the manuscript
defines in section 3.9.2 as the gap between an attack being initiated and an
alert being generated. That needs an independently recorded initiation
timestamp; the first alert is not proof of when the attack began. The two are
kept apart deliberately and neither is derived from the other.

Status
------
:data:`EpisodeStatus.ONGOING`
    Matching activity was observed within the inactivity timeout, so as far
    as the records go it is still happening.
:data:`EpisodeStatus.ENDED`
    Nothing matching has been observed for longer than the timeout. This says
    observation stopped, not that the attacker did.
:data:`EpisodeStatus.UNKNOWN`
    The timestamps needed to decide are missing or inconsistent. Returned
    rather than guessing, and rather than defaulting to either answer.

Status is always computed from stored timestamps against the clock, never
stored. A record that survives a restart is re-evaluated on read, so nothing
is left marked ONGOING by the mere fact that a row exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from aethra_sec.models.enums import StrEnum
from aethra_sec.utils.timeutil import to_utc, utcnow


def _norm(value: datetime | None) -> datetime | None:
    """Put a timestamp on the one scale everything here compares on.

    The application mixes both kinds: values read back from MySQL arrive
    timezone-aware through ``as_dt``, while a caller holding a literal
    may pass a naive one. Comparing the two raises, so every timestamp is
    normalised on the way in rather than at each comparison - a single
    missed call site would otherwise crash the alerts table.
    """
    return None if value is None else to_utc(value)

#: Seconds without a matching observation after which an episode is reported
#: ENDED. The default matches ``detection.suppression_window_seconds`` (120),
#: which is the window the capture service already uses to decide whether a
#: repeat folds into the existing record: inside it a repeat extends the
#: episode, so outside it the episode is by definition no longer being
#: extended. Installations that widen one should widen the other.
DEFAULT_INACTIVITY_SECONDS = 120

#: Settings key for the above.
INACTIVITY_SETTING = "detection.episode_inactivity_seconds"


class EpisodeStatus(StrEnum):
    """Whether an observed episode is still being extended."""

    ONGOING = "ONGOING"
    ENDED = "ENDED"
    UNKNOWN = "UNKNOWN"

    @property
    def label(self) -> str:
        """Short label for the interface."""
        return {
            EpisodeStatus.ONGOING: "Ongoing",
            EpisodeStatus.ENDED: "Ended",
            EpisodeStatus.UNKNOWN: "Unknown",
        }[self]

    @property
    def explanation(self) -> str:
        """One sentence an operator can act on."""
        return {
            EpisodeStatus.ONGOING: (
                "Matching activity was observed recently enough to still be "
                "within the inactivity timeout."
            ),
            EpisodeStatus.ENDED: (
                "Nothing matching has been observed for longer than the "
                "inactivity timeout. Observation stopped; this is not proof "
                "the activity stopped."
            ),
            EpisodeStatus.UNKNOWN: (
                "The timestamps needed to decide are missing or inconsistent, "
                "so no status is claimed."
            ),
        }[self]


def observed_duration(
    first_seen: datetime | None, last_seen: datetime | None
) -> timedelta | None:
    """The span between the first and last observation.

    Returns:
        ``None`` when either timestamp is missing, or when the last precedes
        the first - which means the clocks disagree and no span can be
        trusted. A negative duration is never returned and never clamped to
        zero, because clamping would hide the clock problem behind a
        plausible-looking value.
    """
    first_seen, last_seen = _norm(first_seen), _norm(last_seen)
    if first_seen is None or last_seen is None:
        return None
    span = last_seen - first_seen
    if span < timedelta(0):
        return None
    return span


def format_duration(span: timedelta | None) -> str:
    """Render a span the way an operator reads it.

    ``None`` becomes an em dash rather than "0 seconds", so a missing
    measurement cannot be mistaken for an instantaneous one.
    """
    if span is None:
        return "—"
    total = int(span.total_seconds())
    if total <= 0:
        return "single observation"
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)

    def plural(value: int, unit: str) -> str:
        return f"{value} {unit}" + ("" if value == 1 else "s")

    if days:
        parts = [plural(days, "day")]
        if hours:
            parts.append(plural(hours, "hour"))
        return ", ".join(parts)
    if hours:
        parts = [plural(hours, "hour")]
        if minutes:
            parts.append(plural(minutes, "minute"))
        return ", ".join(parts)
    if minutes:
        parts = [plural(minutes, "minute")]
        if seconds:
            parts.append(plural(seconds, "second"))
        return ", ".join(parts)
    return plural(seconds, "second")


def episode_status(
    first_seen: datetime | None,
    last_seen: datetime | None,
    *,
    inactivity_seconds: int = DEFAULT_INACTIVITY_SECONDS,
    now: datetime | None = None,
) -> EpisodeStatus:
    """Decide whether an episode is still being extended.

    Args:
        inactivity_seconds: how long without a matching observation before
            the episode is reported ENDED.
        now: the reference time, injected so the decision is testable.

    A last-seen timestamp in the future, or one that precedes first-seen,
    yields UNKNOWN: both mean the clocks cannot be trusted, and an episode
    judged on untrustworthy timestamps would be worse than an unjudged one.
    """
    first_seen, last_seen = _norm(first_seen), _norm(last_seen)
    if last_seen is None:
        return EpisodeStatus.UNKNOWN
    if first_seen is not None and last_seen < first_seen:
        return EpisodeStatus.UNKNOWN
    reference = _norm(now) or utcnow()
    # Tolerate a second of clock skew; beyond that the record is ahead of the
    # clock and nothing sensible can be said about it.
    if last_seen > reference + timedelta(seconds=1):
        return EpisodeStatus.UNKNOWN
    timeout = max(1, int(inactivity_seconds))
    if (reference - last_seen) <= timedelta(seconds=timeout):
        return EpisodeStatus.ONGOING
    return EpisodeStatus.ENDED


@dataclass(frozen=True)
class Episode:
    """What is known about one observed episode.

    Built from a stored detection rather than stored itself, so the status is
    always current and a restart cannot leave a stale verdict behind.
    """

    first_seen: datetime | None
    last_seen: datetime | None
    occurrences: int
    status: EpisodeStatus
    duration: timedelta | None

    @property
    def duration_text(self) -> str:
        """The duration as an operator reads it."""
        return format_duration(self.duration)

    @property
    def is_single_observation(self) -> bool:
        """True when the record rests on one sighting.

        Worth asking separately: a single observation has a zero duration,
        and a zero duration must not be read as "the attack was instant".
        """
        return self.occurrences <= 1


def describe(
    first_seen: datetime | None,
    last_seen: datetime | None,
    occurrences: int,
    *,
    inactivity_seconds: int = DEFAULT_INACTIVITY_SECONDS,
    now: datetime | None = None,
) -> Episode:
    """Summarise an episode from the timestamps a detection actually carries."""
    return Episode(
        first_seen=first_seen,
        last_seen=last_seen,
        occurrences=max(1, int(occurrences or 1)),
        status=episode_status(
            first_seen, last_seen,
            inactivity_seconds=inactivity_seconds, now=now,
        ),
        duration=observed_duration(first_seen, last_seen),
    )
