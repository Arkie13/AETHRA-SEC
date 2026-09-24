"""The Dashboard's reporting period (§9, §80, §114).

The Dashboard answers two different kinds of question and used to blur them
into one trailing window. "How much did we see today" is a *period* question,
bounded by calendar dates in the operator's own timezone; "how many incidents
are still open" is a *current state* question with no time bound at all. A
rolling "last 24 hours" answers neither honestly: at 00:05 it still counts
almost all of yesterday.

:class:`DashboardPeriod` is the one authoritative filter every period-scoped
query on the page is given, so no two widgets can describe different spans.

Boundaries
----------
Every period is half-open - ``[start, end)``. A record stamped at exactly
midnight belongs to the day that is beginning, never to both days and never to
neither.

Timezone
--------
Timestamps are stored in UTC. A calendar day, though, is the operator's day, so
each boundary is built as a naive *local wall-clock* time and converted to UTC
by the operating system's timezone database. Constructing it that way is what
makes it correct across a DST transition: the offset in force on the day being
asked about is applied, not the offset in force right now.

Nothing here reads or writes the database. A period is a pair of instants; what
it selects is decided entirely by the query boundaries it is passed into, which
is why changing the period can never alter a stored record.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from aethra_sec.models.enums import StrEnum
from aethra_sec.utils.timeutil import UTC, to_local, to_utc, utcnow


class PeriodMode(StrEnum):
    """What kind of span the Dashboard is reporting over."""

    #: The current local calendar day, ending at the present moment. This is
    #: the only mode that rolls over on its own at midnight.
    TODAY = "TODAY"
    #: One completed local calendar day, chosen by the operator.
    DAY = "DAY"
    #: One local calendar month.
    MONTH = "MONTH"
    #: One local calendar year.
    YEAR = "YEAR"
    #: Everything retained, with no lower bound.
    ALL = "ALL"
    #: An explicit span the operator entered.
    CUSTOM = "CUSTOM"


def local_today(now: datetime | None = None) -> date:
    """The operator's current calendar date."""
    local = to_local(now or utcnow())
    assert local is not None
    return local.date()


def local_midnight(day: date) -> datetime:
    """The UTC instant at which ``day`` begins locally.

    Built from a *naive* local wall-clock time on purpose. ``astimezone`` then
    resolves it with the local offset that applies on that date, so the
    boundary stays correct either side of a DST change - which
    ``now.replace(hour=0, ...)`` would not, because it would carry today's
    offset backwards.
    """
    return datetime(day.year, day.month, day.day).astimezone().astimezone(UTC)


def next_local_midnight(now: datetime | None = None) -> datetime:
    """The UTC instant of the next local midnight after ``now``.

    Derived from the calendar rather than by adding 24 hours, so a DST day of
    23 or 25 hours still lands exactly on 00:00:00 local.
    """
    return local_midnight(local_today(now) + timedelta(days=1))


@dataclass(frozen=True)
class DashboardPeriod:
    """One reporting span, resolved to UTC instants for querying.

    Attributes:
        mode: Which kind of span this is.
        start: Inclusive lower bound in UTC. ``None`` only for
            :attr:`PeriodMode.ALL`, which has no lower bound.
        end: **Exclusive** upper bound in UTC.
        anchor: The local calendar date the span is named after - today's date
            for :attr:`PeriodMode.TODAY`, the first of the month for
            :attr:`PeriodMode.MONTH`, and so on. ``None`` where no single date
            names the span. This is what midnight rollover compares against.
        label: Short name for the control ("Today", "Sep 2026").
        detail: The span in words, for the header line.
    """

    mode: PeriodMode
    start: datetime | None
    end: datetime
    anchor: date | None
    label: str
    detail: str

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def today(cls, now: datetime | None = None) -> "DashboardPeriod":
        """Local midnight today up to the present moment."""
        moment = to_utc(now or utcnow())
        day = local_today(moment)
        start = local_midnight(day)
        local_end = to_local(moment)
        assert local_end is not None
        return cls(
            mode=PeriodMode.TODAY,
            start=start,
            # The present moment, not the end of the day: a period cannot
            # report over hours that have not happened yet.
            end=moment,
            anchor=day,
            label="Today",
            detail=(
                f"{day.strftime('%d %b %Y')}  ·  00:00 - "
                f"{local_end.strftime('%H:%M')}"
            ),
        )

    @classmethod
    def for_day(cls, day: date) -> "DashboardPeriod":
        """One whole local calendar day, ``[00:00, next 00:00)``."""
        return cls(
            mode=PeriodMode.DAY,
            start=local_midnight(day),
            end=local_midnight(day + timedelta(days=1)),
            anchor=day,
            label=day.strftime("%d %b %Y"),
            detail=f"{day.strftime('%d %b %Y')}  ·  00:00 - 24:00",
        )

    @classmethod
    def for_month(cls, year: int, month: int) -> "DashboardPeriod":
        """One whole local calendar month."""
        first = date(year, month, 1)
        last_day = calendar.monthrange(year, month)[1]
        return cls(
            mode=PeriodMode.MONTH,
            start=local_midnight(first),
            end=local_midnight(first + timedelta(days=last_day)),
            anchor=first,
            label=first.strftime("%b %Y"),
            detail=(
                f"{first.strftime('%d %b')} - "
                f"{date(year, month, last_day).strftime('%d %b %Y')}"
            ),
        )

    @classmethod
    def for_year(cls, year: int) -> "DashboardPeriod":
        """One whole local calendar year."""
        first = date(year, 1, 1)
        return cls(
            mode=PeriodMode.YEAR,
            start=local_midnight(first),
            end=local_midnight(date(year + 1, 1, 1)),
            anchor=first,
            label=str(year),
            detail=f"01 Jan - 31 Dec {year}",
        )

    @classmethod
    def all_data(cls, now: datetime | None = None) -> "DashboardPeriod":
        """Everything retained, with no lower bound."""
        moment = to_utc(now or utcnow())
        return cls(
            mode=PeriodMode.ALL,
            start=None,
            end=moment,
            anchor=None,
            label="All data",
            detail="every record retained",
        )

    @classmethod
    def custom(cls, start: datetime, end: datetime) -> "DashboardPeriod":
        """An explicit span. ``end`` stays exclusive, as everywhere else."""
        lower, upper = to_utc(start), to_utc(end)
        if upper < lower:
            lower, upper = upper, lower
        local_lower, local_upper = to_local(lower), to_local(upper)
        assert local_lower is not None and local_upper is not None
        return cls(
            mode=PeriodMode.CUSTOM,
            start=lower,
            end=upper,
            anchor=local_lower.date(),
            label="Custom",
            detail=(
                f"{local_lower.strftime('%d %b %Y %H:%M')} - "
                f"{local_upper.strftime('%d %b %Y %H:%M')}"
            ),
        )

    @classmethod
    def default(cls, now: datetime | None = None) -> "DashboardPeriod":
        """What the Dashboard opens on."""
        return cls.today(now)

    # ------------------------------------------------------------------
    # Behaviour
    # ------------------------------------------------------------------
    @property
    def heading(self) -> str:
        """The period's name as the operator selected it.

        ``str(mode)`` would render the all-data period as "ALL", which is not
        what the control is labelled.
        """
        return "ALL DATA" if self.mode is PeriodMode.ALL else str(self.mode)

    @property
    def tracks_now(self) -> bool:
        """True when the upper bound is "now" and so keeps moving."""
        return self.mode in (PeriodMode.TODAY, PeriodMode.ALL)

    @property
    def rolls_over(self) -> bool:
        """True when a change of calendar date must move this period.

        Only :attr:`PeriodMode.TODAY` does. An operator who navigated to a
        particular day, month or year is investigating history, and silently
        dragging that view forward at midnight would move the ground under an
        investigation in progress.
        """
        return self.mode is PeriodMode.TODAY

    def needs_rollover(self, now: datetime | None = None) -> bool:
        """True when this period no longer describes the current local date."""
        return self.rolls_over and self.anchor != local_today(now)

    def rolled_over(self, now: datetime | None = None) -> "DashboardPeriod":
        """This period advanced to the current date, if it should be."""
        return DashboardPeriod.today(now) if self.needs_rollover(now) else self

    def refreshed(self, now: datetime | None = None) -> "DashboardPeriod":
        """The same span with its moving upper bound brought up to date."""
        if self.mode is PeriodMode.TODAY:
            return DashboardPeriod.today(now)
        if self.mode is PeriodMode.ALL:
            return DashboardPeriod.all_data(now)
        return self

    def contains(self, moment: datetime | None) -> bool:
        """Whether an instant falls inside ``[start, end)``."""
        if moment is None:
            return False
        value = to_utc(moment)
        if self.start is not None and value < self.start:
            return False
        return value < self.end

    @property
    def duration_seconds(self) -> float | None:
        """Length of the span; ``None`` when it has no lower bound."""
        if self.start is None:
            return None
        return (self.end - self.start).total_seconds()

    def previous(self) -> "DashboardPeriod | None":
        """The comparable span immediately before this one, for trend arrows.

        For TODAY that is the same elapsed span of yesterday, so "30% down on
        this time yesterday" compares like with like rather than a partial day
        against a whole one. ``None`` where no comparison is meaningful.
        """
        if self.start is None:
            return None
        if self.mode is PeriodMode.TODAY:
            yesterday = local_midnight(local_today(self.end) - timedelta(days=1))
            elapsed = self.end - self.start
            return DashboardPeriod(
                mode=PeriodMode.CUSTOM, start=yesterday, end=yesterday + elapsed,
                anchor=None, label="Previous", detail="same span yesterday",
            )
        if self.mode is PeriodMode.DAY and self.anchor is not None:
            return DashboardPeriod.for_day(self.anchor - timedelta(days=1))
        if self.mode is PeriodMode.MONTH and self.anchor is not None:
            previous_month_end = self.anchor - timedelta(days=1)
            return DashboardPeriod.for_month(
                previous_month_end.year, previous_month_end.month
            )
        if self.mode is PeriodMode.YEAR and self.anchor is not None:
            return DashboardPeriod.for_year(self.anchor.year - 1)
        return None

    def describe(self) -> dict[str, Any]:
        """Plain values for logging and for the report header."""
        return {
            "mode": str(self.mode),
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat(),
            "label": self.label,
            "detail": self.detail,
        }

#: Named ranges offered by every record-list period filter, in menu order.
#:
#: One list, shared by the IDS Alerts and Threat Incidents screens, so the two
#: offer the same choices under the same names and a range means the same thing
#: on both. They had drifted apart - one said "All time" and the other "All
#: data", one offered "Last hour" and the other "This month" - which made the
#: two screens hard to compare for the same span.
#:
#: The trailing windows ("Last hour", "Last 24 hours") end at the present
#: moment; the calendar ones snap to local midnight. ``Custom...`` is answered
#: by the screen, which asks for the two bounds.
NAMED_RANGES: tuple[str, ...] = (
    "Today",
    "Yesterday",
    "Last hour",
    "Last 24 hours",
    "Last 7 days",
    "Last 30 days",
    "This month",
    "Previous month",
    "This year",
    "All data",
    "Custom...",
)

#: Ranges that end now rather than on a calendar boundary, and how far back
#: each reaches.
_TRAILING_HOURS: dict[str, float] = {
    "last hour": 1.0,
    "last 24 hours": 24.0,
}


#: The range option that asks the operator for explicit bounds.
CUSTOM_RANGE = "Custom..."


def parse_moment(raw: object) -> datetime | None:
    """Parse ``YYYY-MM-DD HH:MM`` as local wall-clock time, or ``None``.

    Returned as UTC, resolved through the local timezone exactly as every
    other boundary is, so a custom range and a named range agree about where a
    day begins. A value that does not parse returns ``None`` rather than a
    guess: a filter nobody asked for would show the wrong records.

    Defined here so the screens that offer a custom range share one parser -
    three copies of this would eventually disagree about what a date means.
    """
    text = str(raw or "").strip().replace("T", " ")
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern).astimezone()
        except ValueError:
            continue
    return None


def period_for_range(label: str, now: datetime | None = None) -> "DashboardPeriod | None":
    """Resolve a named range to a period.

    Every range is built from :class:`DashboardPeriod`, so a filter on a record
    list and the Dashboard's reporting period compute their bounds the same
    way: local calendar dates, resolved through the machine's timezone, and
    half-open so a record stamped at midnight belongs to one day only.

    "Last 7 days" means the last seven *calendar* days including today, not a
    168-hour trailing window - a trailing window drifts through the day and
    makes two runs of the same filter disagree.

    Returns:
        The period, or ``None`` for ``Custom...``, which the caller resolves
        by asking for the bounds.
    """
    moment = to_utc(now or utcnow())
    today = local_today(moment)
    name = (label or "").strip().lower()

    hours = _TRAILING_HOURS.get(name)
    if hours is not None:
        start = moment - timedelta(hours=hours)
        return DashboardPeriod(
            mode=PeriodMode.CUSTOM, start=start, end=moment, anchor=today,
            label=label, detail=(
                f"{to_local(start).strftime('%d %b %H:%M')} - "
                f"{to_local(moment).strftime('%d %b %H:%M')}"
            ),
        )
    if name == "today":
        return DashboardPeriod.today(moment)
    if name == "yesterday":
        return DashboardPeriod.for_day(today - timedelta(days=1))
    if name in ("last 7 days", "last 30 days"):
        days = 7 if "7" in name else 30
        start = local_midnight(today - timedelta(days=days - 1))
        return DashboardPeriod(
            mode=PeriodMode.CUSTOM, start=start, end=moment, anchor=today,
            label=label, detail=(
                f"{(today - timedelta(days=days - 1)).strftime('%d %b %Y')} - "
                f"{today.strftime('%d %b %Y')}"
            ),
        )
    if name == "this month":
        return DashboardPeriod.for_month(today.year, today.month)
    if name == "previous month":
        last = date(today.year, today.month, 1) - timedelta(days=1)
        return DashboardPeriod.for_month(last.year, last.month)
    if name == "this year":
        return DashboardPeriod.for_year(today.year)
    if name in ("all data", "all time"):
        return DashboardPeriod.all_data(moment)
    return None
