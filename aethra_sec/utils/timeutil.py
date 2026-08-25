"""Time handling.

AETHRA-SEC stores every timestamp in UTC (``DATETIME(6)``) and converts to the
operator's local time only for display. Detection-time measurements always use
real observed event timestamps; no timestamp is ever invented.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = timezone.utc


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def to_utc(value: datetime) -> datetime:
    """Convert any datetime to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC, which matches how values are
    read back from MySQL ``DATETIME`` columns.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def to_db(value: datetime | None) -> datetime | None:
    """Normalise a datetime for storage (naive UTC, as MySQL expects)."""
    if value is None:
        return None
    return to_utc(value).replace(tzinfo=None)


def from_db(value: datetime | None) -> datetime | None:
    """Interpret a datetime read from MySQL as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def to_local(value: datetime | None) -> datetime | None:
    """Convert a stored UTC datetime to the machine's local timezone."""
    if value is None:
        return None
    return to_utc(value).astimezone()


def from_epoch(seconds: float) -> datetime:
    """Convert a POSIX timestamp (e.g. a PyShark sniff time) to UTC."""
    return datetime.fromtimestamp(seconds, tz=UTC)


def format_local(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a stored UTC timestamp in local time, or ``-`` when absent."""
    local = to_local(value)
    return local.strftime(fmt) if local else "-"


def format_local_ms(value: datetime | None) -> str:
    """Format a stored UTC timestamp in local time with milliseconds."""
    local = to_local(value)
    if not local:
        return "-"
    return f"{local.strftime('%H:%M:%S')}.{local.microsecond // 1000:03d}"


def format_duration(seconds: float | None) -> str:
    """Render a duration compactly (``1.25 s``, ``3m 04s``, ``2h 15m``)."""
    if seconds is None:
        return "-"
    if seconds < 0:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60):02d}s"
    if seconds < 86_400:
        return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60):02d}m"
    return f"{int(seconds // 86_400)}d {int((seconds % 86_400) // 3600):02d}h"


def format_uptime(started: datetime | None, now: datetime | None = None) -> str:
    """Uptime string derived from a real start timestamp."""
    if started is None:
        return "Not started"
    reference = now or utcnow()
    return format_duration((to_utc(reference) - to_utc(started)).total_seconds())


def age_seconds(value: datetime | None, now: datetime | None = None) -> float | None:
    """Seconds elapsed since ``value``; ``None`` when ``value`` is absent."""
    if value is None:
        return None
    reference = to_utc(now or utcnow())
    return (reference - to_utc(value)).total_seconds()


def window_start(seconds: int, now: datetime | None = None) -> datetime:
    """UTC datetime marking the start of a trailing window."""
    return to_utc(now or utcnow()) - timedelta(seconds=seconds)
