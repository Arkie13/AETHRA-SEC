"""Progressive sign-in lockout, derived from recorded attempts (§118).

The rule is simple to state: three consecutive failures lock sign-in for that
identifier, and each further group of three locks it for longer - 30 seconds,
then 60, then 120, then 300, and 300 thereafter.

Where the state lives
---------------------
Nowhere new. The lock is *computed* from ``login_attempts``, which the
application has always written a row to on every attempt, successful or not.
That choice settles several requirements at once and it is worth being explicit
about why:

* **It survives a restart.** There is no in-memory counter to lose and no cache
  to warm; closing and reopening AETHRA-SEC re-derives the same lock from the
  same rows.
* **It cannot be bypassed from the interface.** A client countdown is a
  courtesy. The decision is made here, on the server side of the call, before a
  password is looked at.
* **It does not disclose whether an account exists.** The identifier is the
  *submitted username string*, and a row is recorded for an unknown name just
  as it is for a real one. Three attempts against ``nosuchuser`` lock exactly
  as three against ``admin`` do, and the reply is identical - so an attacker
  learns nothing by watching for a lock. Keying the throttle on the account row
  instead would have made the lock itself an enumeration oracle.

The counter is *consecutive*: a successful sign-in ends the run, so the next
failure starts again at one. The attempt rows themselves are never rewritten -
the audit history of what happened is not edited by the fact that someone later
got their password right.

Nothing here reads a password, a hash, or a session token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

#: Consecutive failures that trigger a lock, and each further escalation.
FAILURES_BEFORE_LOCK = 3

#: Lock duration in seconds for each successive escalation. The last value is
#: the cap: locks stop growing rather than becoming unbounded, so a legitimate
#: operator who has genuinely forgotten a password is never denied for good.
BACKOFF_SECONDS: tuple[int, ...] = (30, 60, 120, 300)

#: Failures within :data:`ALERT_WINDOW_MINUTES` that make this worth telling an
#: administrator about. Higher than the lock threshold on purpose: one person
#: mistyping a password three times is not a security event, and paging an
#: administrator for it would train them to ignore the alert that matters.
ALERT_THRESHOLD = 5
ALERT_WINDOW_MINUTES = 15


def lockout_seconds(level: int) -> int:
    """How long the lock lasts at escalation ``level`` (0-based)."""
    if level < 0:
        return 0
    index = min(level, len(BACKOFF_SECONDS) - 1)
    return BACKOFF_SECONDS[index]


@dataclass(frozen=True)
class LockoutState:
    """Whether sign-in is currently allowed for one identifier.

    Attributes:
        failures: consecutive failed attempts since the last success.
        level: escalation reached, 0-based. ``-1`` when no lock has triggered.
        locked_until: instant the lock expires, or ``None`` when not locked.
        seconds: the lock's full duration, for the audit record.
    """

    failures: int = 0
    level: int = -1
    locked_until: datetime | None = None
    seconds: int = 0

    @property
    def locked(self) -> bool:
        """True while sign-in must be refused."""
        return self.locked_until is not None

    def remaining(self, now: datetime) -> int:
        """Whole seconds left on the lock, never negative."""
        if self.locked_until is None:
            return 0
        return max(0, int((self.locked_until - now).total_seconds() + 0.999))

    @property
    def attempts_until_lock(self) -> int:
        """Failures still allowed before the next lock triggers."""
        if self.locked:
            return 0
        return max(0, FAILURES_BEFORE_LOCK - (self.failures % FAILURES_BEFORE_LOCK))


def evaluate(
    consecutive_failures: int,
    last_failure_at: datetime | None,
    now: datetime,
) -> LockoutState:
    """Decide the lock state from a real run of consecutive failures.

    A lock triggers on every multiple of :data:`FAILURES_BEFORE_LOCK` and runs
    from the failure that triggered it, so the duration is measured from a
    recorded event rather than from when this happens to be called.

    Args:
        consecutive_failures: failures since the identifier last succeeded.
        last_failure_at: when the most recent of them was recorded.
        now: current time, supplied so the decision is testable.

    Returns:
        The state. ``locked`` is false once the window has elapsed, without
        anything having to expire it - there is no state to clear.
    """
    failures = max(0, int(consecutive_failures))
    if failures < FAILURES_BEFORE_LOCK or last_failure_at is None:
        return LockoutState(failures=failures)

    level = failures // FAILURES_BEFORE_LOCK - 1
    seconds = lockout_seconds(level)
    expires = last_failure_at + timedelta(seconds=seconds)
    if now >= expires:
        # The lock has run its course. The failures are still on the record -
        # the next one escalates - but sign-in is allowed to proceed.
        return LockoutState(failures=failures, level=level, seconds=seconds)
    return LockoutState(
        failures=failures, level=level, locked_until=expires, seconds=seconds
    )


def format_remaining(seconds: int) -> str:
    """``MM:SS`` for the countdown on the sign-in screen."""
    seconds = max(0, int(seconds))
    return f"{seconds // 60:02d}:{seconds % 60:02d}"
