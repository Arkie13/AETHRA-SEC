"""Progressive sign-in lockout and the administrator alert (§118).

Three consecutive failures lock sign-in for 30 seconds, and each further group
of three locks it for longer - 60, 120, 300, then 300 as the cap. A run of
failures that reaches the alerting threshold tells an administrator once,
not once per attempt.

Three properties are pinned, and the third is the one most easily lost.

**The decision is made on the server side.** The lock is derived from rows in
``login_attempts``, so it survives a restart, cannot be shortened by a client
clock, and refuses a *correct* password while it stands.

**A success ends the run but not the record.** The consecutive counter starts
again; the attempt rows and the audit trail are untouched, because what
happened is not edited by what happened next.

**A lock discloses nothing about whether an account exists.** The throttle is
keyed on the submitted username string, and an unknown name accumulates and
locks byte-identically to a real one. Keying it on the account row would have
turned the lock itself into an enumeration oracle - three guesses against any
name, and the presence of a lock would answer the question.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aethra_sec.security import lockout
from aethra_sec.security.authentication import (
    GENERIC_FAILURE_MESSAGE,
    AuthenticationService,
)
from aethra_sec.security.lockout import (
    ALERT_THRESHOLD,
    ALERT_WINDOW_MINUTES,
    BACKOFF_SECONDS,
    FAILURES_BEFORE_LOCK,
    LockoutState,
    evaluate,
    format_remaining,
    lockout_seconds,
)
from aethra_sec.utils.timeutil import UTC

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
AUTH = PACKAGE / "security" / "authentication.py"
LOGIN = PACKAGE / "ui" / "login.py"

NOW = datetime(2026, 9, 7, 18, 32, 0, tzinfo=UTC)


def _statements(path: Path) -> str:
    """Source with docstrings removed, so prose is not mistaken for code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


# ---------------------------------------------------------------------------
# The schedule
# ---------------------------------------------------------------------------
class TestTheLockoutSchedule:
    """3 -> 30s, then 60, 120, 300, capped."""

    def test_the_threshold_is_three(self) -> None:
        assert FAILURES_BEFORE_LOCK == 3

    def test_the_backoff_schedule(self) -> None:
        assert BACKOFF_SECONDS == (30, 60, 120, 300)

    @pytest.mark.parametrize(
        ("failures", "seconds"),
        [(3, 30), (6, 60), (9, 120), (12, 300), (15, 300), (300, 300)],
    )
    def test_each_group_of_three_escalates(
        self, failures: int, seconds: int
    ) -> None:
        state = evaluate(failures, NOW, NOW)
        assert state.locked
        assert state.seconds == seconds

    @pytest.mark.parametrize("failures", [0, 1, 2])
    def test_fewer_than_three_does_not_lock(self, failures: int) -> None:
        assert not evaluate(failures, NOW, NOW).locked

    def test_the_lock_is_capped_not_unbounded(self) -> None:
        """A legitimate operator must never be denied for good."""
        assert lockout_seconds(999) == max(BACKOFF_SECONDS)
        assert max(BACKOFF_SECONDS) <= 600

    def test_the_lock_expires_on_its_own(self) -> None:
        state = evaluate(3, NOW, NOW + timedelta(seconds=30))
        assert not state.locked
        assert state.failures == 3, "the failures stay on the record"

    def test_the_lock_is_measured_from_the_recorded_failure(self) -> None:
        """Not from when the check happens to run."""
        state = evaluate(3, NOW, NOW + timedelta(seconds=10))
        assert state.remaining(NOW + timedelta(seconds=10)) == 20

    def test_the_countdown_is_minutes_and_seconds(self) -> None:
        assert format_remaining(30) == "00:30"
        assert format_remaining(120) == "02:00"
        assert format_remaining(0) == "00:00"
        assert format_remaining(-5) == "00:00"

    def test_no_lock_without_a_recorded_failure_time(self) -> None:
        """A count with no timestamp cannot say when the lock ends."""
        assert not evaluate(9, None, NOW).locked


# ---------------------------------------------------------------------------
# Server-side enforcement
# ---------------------------------------------------------------------------
class TestTheServerDecides:
    """The interface displays the lock; it never decides it."""

    def test_the_state_is_derived_from_recorded_attempts(self) -> None:
        source = inspect.getsource(AuthenticationService._lockout_for)
        assert "consecutive_failures" in source
        assert "evaluate(" in source

    def test_the_throttle_runs_before_the_password_is_examined(self) -> None:
        """So a correct password cannot get in during a lock."""
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index("\n    def ", 1)]
        assert login.index("_lockout_for") < login.index("verify("), (
            "the password is verified before the throttle, so a correct "
            "password would be accepted while sign-in is locked"
        )

    def test_a_lock_raises_rather_than_returning_a_session(self) -> None:
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index("\n    def ", 1)]
        assert "raise AccountLockedError" in login

    def test_nothing_in_the_service_trusts_a_client_clock(self) -> None:
        source = inspect.getsource(AuthenticationService)
        assert "utcnow()" in source

    def test_the_screen_only_reads_the_status(self) -> None:
        """``lockout_status`` returns a display value and grants nothing."""
        signature = inspect.signature(AuthenticationService.lockout_status)
        assert list(signature.parameters) == ["self", "username"]
        source = inspect.getsource(AuthenticationService.lockout_status)
        assert "Session" not in source
        assert "return lock.locked" in source

    def test_the_login_screen_asks_the_server(self) -> None:
        code = _statements(LOGIN)
        assert "authentication.lockout_status(username)" in code

    def test_the_countdown_re_asks_rather_than_unlocking_itself(self) -> None:
        """When the client clock runs out, the server is asked again."""
        code = _statements(LOGIN)
        tick = code[code.index("def _tick_lock_countdown"):]
        tick = tick[: tick.index("\n    def ", 1)]
        assert "_refresh_lock_state" in tick

    def test_no_lockout_state_is_kept_in_a_ui_file(self) -> None:
        """No counter the interface could reset by restarting."""
        code = _statements(LOGIN)
        for forbidden in ("failed_count", "attempt_count", "_failures ="):
            assert forbidden not in code


class TestARestartDoesNotClearTheLock:
    """There is no in-memory counter to lose."""

    def test_the_service_holds_no_attempt_counter(self) -> None:
        source = inspect.getsource(AuthenticationService.__init__)
        for forbidden in ("_failures", "_attempts", "_lock_cache"):
            assert forbidden not in source

    def test_the_state_comes_from_the_database_every_time(self) -> None:
        source = inspect.getsource(AuthenticationService._lockout_for)
        assert "self._users" in source


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------
class TestNoUsernameEnumeration:
    """An unknown name must behave exactly like a real one."""

    def test_the_throttle_is_keyed_on_the_submitted_name(self) -> None:
        from aethra_sec.database.repositories.users import UserRepository

        source = inspect.getsource(UserRepository.consecutive_failures)
        assert "username = %s" in source
        assert "user_id" not in source, (
            "keying the throttle on the account row makes the lock itself an "
            "enumeration oracle"
        )

    def test_an_unknown_username_escalates_too(self) -> None:
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index("\n    def ", 1)]
        unknown = login[login.index("unknown_user"):]
        assert "_lockout_for" in unknown
        assert "AccountLockedError" in unknown

    def test_the_credential_failure_message_is_one_string(self) -> None:
        assert GENERIC_FAILURE_MESSAGE == "Invalid username or password."
        code = _statements(AUTH)
        assert "does not exist" not in code
        assert "no such user" not in code.lower()

    def test_the_lock_message_names_only_the_wait(self) -> None:
        state = LockoutState(
            failures=3, level=0, locked_until=NOW + timedelta(seconds=30),
            seconds=30,
        )
        message = AuthenticationService._lockout_message(state)
        assert "Too many unsuccessful login attempts" in message
        assert "Try again in" in message
        for leak in ("exist", "account", "threshold", "admin"):
            assert leak not in message.lower()


# ---------------------------------------------------------------------------
# Administrator alerting
# ---------------------------------------------------------------------------
class TestTheAdministratorAlert:
    """Real events only, and not one per attempt."""

    def test_the_threshold_is_above_the_lock_threshold(self) -> None:
        """Three mistyped passwords is not a security event."""
        assert ALERT_THRESHOLD > FAILURES_BEFORE_LOCK
        assert ALERT_WINDOW_MINUTES > 0

    def test_the_alert_counts_real_recorded_attempts(self) -> None:
        source = inspect.getsource(AuthenticationService._raise_security_alert)
        assert "failed_attempts_since" in source
        assert f"recent < ALERT_THRESHOLD" in source

    def test_no_alert_below_the_threshold(self) -> None:
        """Read from the statements: the docstring names the constant too."""
        code = _statements(AUTH)
        action = code[code.index("def _raise_security_alert"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        guard = action[action.index("ALERT_THRESHOLD"):]
        assert "return" in guard[:60], (
            "the threshold is read but does not stop the alert"
        )

    def test_it_is_deduplicated(self) -> None:
        source = inspect.getsource(AuthenticationService._raise_security_alert)
        assert "security_alert_exists" in source

    def test_it_uses_the_existing_notification_pipeline(self) -> None:
        """Not a second notification framework."""
        from aethra_sec.services.notification_service import NotificationService

        assert hasattr(NotificationService, "raise_security_alert")
        source = inspect.getsource(NotificationService.raise_security_alert)
        assert "self._store" in source, (
            "the alert bypasses the pipeline every other notification uses"
        )

    def test_the_alert_carries_no_secret(self) -> None:
        source = inspect.getsource(AuthenticationService._raise_security_alert)
        for forbidden in ("password", "stored_hash", "token", "hash"):
            assert forbidden not in source.split('"""')[-1]

    def test_the_alert_is_audited_under_its_own_action(self) -> None:
        from aethra_sec.security.audit import AuditAction

        assert str(AuditAction.MULTIPLE_LOGIN_FAILURES) == (
            "MULTIPLE_LOGIN_FAILURES_DETECTED"
        )

    def test_the_correlation_key_is_hidden_from_the_operator(self) -> None:
        from aethra_sec.models.system import Notification

        note = Notification(
            title="Multiple failed login attempts",
            message="8 failed attempts.⁣ref:login-failures:admin",
        )
        assert note.display_message == "8 failed attempts."
        assert "ref:" not in note.display_message

    def test_the_alert_level_does_not_start_a_repeating_alarm(self) -> None:
        """CRITICAL re-sounds until acknowledged; caps lock should not."""
        from aethra_sec.services.notification_service import NotificationService

        source = inspect.getsource(NotificationService.raise_security_alert)
        assert "NotificationLevel.WARNING" in source
        assert "NotificationLevel.CRITICAL" not in source

    def test_alerting_never_blocks_the_lockout(self) -> None:
        """The control that refuses sign-in must not depend on reporting it."""
        source = inspect.getsource(AuthenticationService._raise_security_alert)
        assert "if self._notifications is None:" in source
        assert source.count("except Exception") >= 3


# ---------------------------------------------------------------------------
# What must not have changed
# ---------------------------------------------------------------------------
class TestAdminIsNotExempt:
    """The most valuable account keeps the same protection."""

    def test_no_role_is_consulted_by_the_throttle(self) -> None:
        source = inspect.getsource(AuthenticationService._lockout_for)
        assert "role" not in source.lower()

    def test_the_lock_check_precedes_any_role_logic(self) -> None:
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index("\n    def ", 1)]
        before = login[: login.index("_lockout_for")]
        assert "role" not in before.lower()

    def test_the_policy_module_has_no_exemption_list(self) -> None:
        code = _statements(PACKAGE / "security" / "lockout.py")
        for forbidden in ("ADMIN", "exempt", "bypass", "allowlist"):
            assert forbidden not in code


class TestThereIsNoSecondFactor:
    """A correct password is a session, with nothing in between.

    The second factor was removed. These tests are the guard that keeps it
    removed: a half-authenticated state is the thing that would have to come
    back first, so they assert that no such state can be expressed.
    """

    def test_the_login_result_cannot_express_a_pending_challenge(self) -> None:
        from aethra_sec.security.authentication import LoginResult

        fields = set(LoginResult.__dataclass_fields__)
        assert fields == {"session", "must_change_password"}

    def test_a_verified_password_returns_a_session_directly(self) -> None:
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index(chr(10) + "    def ", 1)]
        assert "_establish_session(user, host)" in login
        for removed in ("otp", "required_for", "second factor", "verification code"):
            assert removed not in login.lower(), removed

    def test_no_otp_module_remains(self) -> None:
        assert not (PACKAGE / "security" / "otp.py").exists()

    def test_the_service_takes_no_otp_collaborator(self) -> None:
        import inspect as _inspect

        from aethra_sec.security.authentication import AuthenticationService

        parameters = _inspect.signature(AuthenticationService.__init__).parameters
        assert "otp" not in parameters

    def test_the_lockout_is_still_checked_before_the_password(self) -> None:
        """Removing the second factor must not move the throttle."""
        code = _statements(AUTH)
        login = code[code.index("def login"):]
        login = login[: login.index(chr(10) + "    def ", 1)]
        assert login.index("_lockout_for") < login.index("get_by_username")


class TestTheAuditTrailIsComplete:
    """Every authentication-security event is recorded."""

    @pytest.mark.parametrize(
        "action",
        ["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKED",
         "MULTIPLE_LOGIN_FAILURES"],
    )
    def test_the_action_exists(self, action: str) -> None:
        from aethra_sec.security.audit import AuditAction

        assert hasattr(AuditAction, action)

    def test_a_lock_records_its_duration(self) -> None:
        code = _statements(AUTH)
        assert "lock.seconds" in code

    def test_no_password_reaches_the_audit_trail(self) -> None:
        code = _statements(AUTH)
        for call in ("detail=password", "detail=f'{password}", "str(password)"):
            assert call not in code

    def test_the_lockout_module_never_sees_a_credential(self) -> None:
        code = _statements(PACKAGE / "security" / "lockout.py")
        for forbidden in ("password", "hash", "token", "secret"):
            assert forbidden not in code.lower()


class TestNothingIsFabricated:
    """No sample alerts, no invented attempts."""

    def test_the_lockout_module_reads_no_clock_of_its_own(self) -> None:
        """``now`` is passed in, so a decision is reproducible and testable."""
        source = inspect.getsource(evaluate)
        assert "utcnow()" not in source
        assert "now" in inspect.signature(evaluate).parameters

    def test_nothing_generates_an_attempt(self) -> None:
        code = _statements(PACKAGE / "security" / "lockout.py")
        for forbidden in ("random", "sample", "INSERT", "fake", "demo"):
            assert forbidden not in code

    def test_the_alert_text_is_built_from_counted_rows(self) -> None:
        source = inspect.getsource(AuthenticationService._raise_security_alert)
        assert "{recent}" in source
        for forbidden in ("random", "choice("):
            assert forbidden not in source

    def test_the_module_defines_the_policy_in_one_place(self) -> None:
        """A second copy of the schedule would drift from this one."""
        defining = [
            path
            for path in PACKAGE.rglob("*.py")
            if "__pycache__" not in path.parts
            and "BACKOFF_SECONDS: tuple" in path.read_text(encoding="utf-8")
        ]
        assert [p.name for p in defining] == ["lockout.py"]
        assert lockout.__name__.endswith("lockout")
