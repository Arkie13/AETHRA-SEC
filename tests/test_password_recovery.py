"""Administrator-approved password recovery, and the RBAC around it (§6, §8, §70).

The properties these tests hold to are the ones that make the feature safe:

* a request changes **nothing** - the password stays as it was until an
  administrator decides and the owner redeems a code;
* the sign-in form cannot be used to discover which usernames exist;
* approving requires a permission the standard role does not hold, and the
  refusal is enforced in the service, not the interface;
* a code works once, for one account, for a bounded time, and a wrong code is
  counted until the approval is revoked;
* every step is written to the audit trail, and the code itself never is.

The database-backed cases skip themselves when no MySQL-compatible server is
reachable, exactly like the rest of the suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from aethra_sec.core.errors import (
    AuthenticationError,
    PermissionDeniedError,
    ValidationFailedError,
)
from aethra_sec.core.permissions import (
    ADMIN_PERMISSIONS,
    USER_PERMISSIONS,
    Permission,
    PermissionSet,
)
from aethra_sec.core.session import Session, SessionManager
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.repositories import (
    AuditRepository,
    PasswordResetRepository,
    UserRepository,
)
from aethra_sec.models.user import PasswordResetRequest, ResetStatus
from aethra_sec.security.audit import AuditAction, AuditService
from aethra_sec.security.authentication import (
    AuthenticationPolicy,
    AuthenticationService,
)
from aethra_sec.security.password import (
    PasswordHashService,
    code_fingerprint,
    generate_recovery_code,
    normalise_recovery_code,
)
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.recovery_service import (
    REQUEST_ACKNOWLEDGEMENT,
    PasswordRecoveryService,
    RecoveryPolicy,
)
from aethra_sec.services.user_service import UserService
from aethra_sec.utils.timeutil import to_db, utcnow

ADMIN_PASSWORD = "AdminPass!2026"
ANALYST_PASSWORD = "AnalystPass!2026"
NEW_PASSWORD = "Recovered!Pass2026"


# ---------------------------------------------------------------------------
# Pure logic: codes, permissions and request expiry
# ---------------------------------------------------------------------------
class TestRecoveryCodes:
    """The one-time code and how it is stored."""

    def test_code_has_a_readable_shape(self) -> None:
        """Four groups of four, so it can be dictated over a phone."""
        code = generate_recovery_code()
        groups = code.split("-")
        assert len(groups) == 4
        assert all(len(group) == 4 for group in groups)

    def test_code_omits_ambiguous_characters(self) -> None:
        """O/0, I/1 and S/5 are never mixed in a code someone reads aloud."""
        codes = "".join(generate_recovery_code() for _ in range(200))
        for ambiguous in "O0I1S5":
            assert ambiguous not in codes

    def test_codes_are_unique(self) -> None:
        """Two approvals never mint the same code."""
        codes = {generate_recovery_code() for _ in range(500)}
        assert len(codes) == 500

    def test_normalisation_ignores_formatting(self) -> None:
        """Case, spaces and hyphens are cosmetic; the value is not."""
        assert normalise_recovery_code("abcd-efgh") == "ABCDEFGH"
        assert normalise_recovery_code(" a b c d ") == "ABCD"
        assert normalise_recovery_code("") == ""

    def test_fingerprint_is_stable_and_hides_the_code(self) -> None:
        """Equivalent spellings hash the same; the digest reveals nothing."""
        code = generate_recovery_code()
        assert code_fingerprint(code) == code_fingerprint(code.lower().replace("-", " "))
        assert code_fingerprint(code) != code_fingerprint(generate_recovery_code())
        digest = code_fingerprint(code)
        assert len(digest) == 64
        assert normalise_recovery_code(code) not in digest


class TestRecoveryPermission:
    """Approving recovery is an administrative capability."""

    def test_standard_role_cannot_approve(self) -> None:
        """USER holds no recovery permission at all."""
        assert Permission.USER_RESET_APPROVE not in USER_PERMISSIONS
        assert Permission.USER_MANAGE not in USER_PERMISSIONS
        assert not PermissionSet.for_role("USER").has(Permission.USER_RESET_APPROVE)

    def test_administrator_can_approve(self) -> None:
        """ADMIN holds it, as it holds every permission."""
        assert Permission.USER_RESET_APPROVE in ADMIN_PERMISSIONS
        assert PermissionSet.for_role("ADMIN").has(Permission.USER_RESET_APPROVE)


class TestRequestExpiry:
    """A request and its approval have different, deliberate deadlines."""

    def test_pending_request_expires_on_its_review_window(self) -> None:
        """Nobody reviewed it in time."""
        now = utcnow()
        request = PasswordResetRequest(
            id=1, user_id=1, username="analyst",
            status=ResetStatus.PENDING, expires_at=now - timedelta(minutes=1),
        )
        assert request.has_expired(now)
        request.expires_at = now + timedelta(hours=1)
        assert not request.has_expired(now)

    def test_approved_request_expires_on_its_code_deadline(self) -> None:
        """The approval, not the original request, bounds the code."""
        now = utcnow()
        request = PasswordResetRequest(
            id=1, user_id=1, username="analyst", status=ResetStatus.APPROVED,
            expires_at=now + timedelta(hours=10),
            code_expires_at=now - timedelta(seconds=1),
        )
        assert request.has_expired(now)

    def test_decided_requests_do_not_expire_further(self) -> None:
        """A completed or rejected request is already final."""
        now = utcnow()
        for status in (ResetStatus.COMPLETED, ResetStatus.REJECTED, ResetStatus.EXPIRED):
            request = PasswordResetRequest(
                id=1, user_id=1, username="analyst", status=status,
                expires_at=now - timedelta(days=5),
            )
            assert not request.has_expired(now)


# ---------------------------------------------------------------------------
# Database-backed workflow
# ---------------------------------------------------------------------------
@dataclass
class RecoveryStack:
    """Everything a recovery test needs, wired against the test schema."""

    recovery: PasswordRecoveryService
    users_service: UserService
    authentication: AuthenticationService
    requests: PasswordResetRepository
    users: UserRepository
    audit: AuditService
    sessions: SessionManager
    admin_session: Session
    analyst_session: Session
    analyst_id: int
    db: DatabaseManager

    def audit_actions(self) -> list[str]:
        """Every audited action, newest last."""
        rows = self.db.query(
            "SELECT action, result, detail FROM audit_logs ORDER BY id"
        )
        return [str(row["action"]) for row in rows]

    def audit_details(self) -> str:
        """Every audit detail concatenated, for 'is the code in here?' checks."""
        rows = self.db.query("SELECT detail FROM audit_logs")
        return "\n".join(str(row["detail"] or "") for row in rows)


@pytest.fixture
def recovery_stack(clean_db: DatabaseManager) -> RecoveryStack:
    """An administrator, an analyst and the full recovery service."""
    db = clean_db
    users = UserRepository(db)
    requests = PasswordResetRepository(db)
    audit = AuditService(AuditRepository(db))
    sessions = SessionManager(60)
    passwords = PasswordHashService(prefer_argon2=False)  # fast for tests
    policy = AuthenticationPolicy(max_failed_logins=5, password_min_length=12)
    authentication = AuthenticationService(
        users, sessions, passwords, audit, None, policy
    )
    access = AccessControl(sessions, audit)
    users_service = UserService(users, passwords, authentication, audit, access)
    recovery = PasswordRecoveryService(
        requests, users, passwords, authentication, audit, access,
        RecoveryPolicy(
            request_ttl_hours=24, code_ttl_minutes=60, max_code_attempts=3,
            max_requests_per_day=2,
        ),
    )

    admin_role = users.get_role_by_name("ADMIN")
    user_role = users.get_role_by_name("USER")
    assert admin_role and admin_role.id and user_role and user_role.id

    admin_hash = passwords.hash(ADMIN_PASSWORD)
    admin_id = users.create_user(
        username="admin", password_hash=admin_hash.hash,
        password_algorithm=admin_hash.algorithm, role_id=admin_role.id,
        full_name="Administrator",
    )
    analyst_hash = passwords.hash(ANALYST_PASSWORD)
    analyst_id = users.create_user(
        username="analyst", password_hash=analyst_hash.hash,
        password_algorithm=analyst_hash.algorithm, role_id=user_role.id,
        full_name="Analyst",
    )

    admin_session = sessions.create(
        user_id=admin_id, username="admin", role="ADMIN",
        permissions=users.permissions_for_user(admin_id),
    )
    analyst_session = sessions.create(
        user_id=analyst_id, username="analyst", role="USER",
        permissions=users.permissions_for_user(analyst_id),
    )
    return RecoveryStack(
        recovery=recovery, users_service=users_service,
        authentication=authentication, requests=requests, users=users,
        audit=audit, sessions=sessions, admin_session=admin_session,
        analyst_session=analyst_session, analyst_id=analyst_id, db=db,
    )


def _approve_latest(stack: RecoveryStack, note: str = "verified in person") -> str:
    """Approve the analyst's open request and return the issued code."""
    request = stack.requests.open_for_user(stack.analyst_id)
    assert request is not None and request.id is not None
    return stack.recovery.approve(stack.admin_session, request.id, note=note).code


class TestRaisingARequest:
    """Step 1: the sign-in screen queues a request and changes nothing."""

    def test_request_is_queued_for_review(self, recovery_stack: RecoveryStack) -> None:
        """A real account gets a pending row naming who asked and from where."""
        answer = recovery_stack.recovery.request_reset(
            "analyst", reason="Forgot it after the holiday",
            contact="analyst@example.org", host_context="WS-014",
        )
        assert answer == REQUEST_ACKNOWLEDGEMENT

        request = recovery_stack.requests.open_for_user(recovery_stack.analyst_id)
        assert request is not None
        assert request.status == ResetStatus.PENDING
        assert request.username == "analyst"
        assert request.reason == "Forgot it after the holiday"
        assert request.contact == "analyst@example.org"
        assert request.host_context == "WS-014"
        assert request.expires_at is not None

    def test_request_does_not_change_the_password(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The whole point: asking is not getting."""
        recovery_stack.recovery.request_reset("analyst")
        assert recovery_stack.authentication.login(
            "analyst", ANALYST_PASSWORD
        ).authenticated

    def test_unknown_account_answers_identically(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The form cannot be used to find out which usernames exist (§62)."""
        known = recovery_stack.recovery.request_reset("analyst")
        unknown = recovery_stack.recovery.request_reset("nosuchperson")
        malformed = recovery_stack.recovery.request_reset("!! not a username !!")
        assert known == unknown == malformed == REQUEST_ACKNOWLEDGEMENT

    def test_unknown_account_queues_nothing(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """A probe must not be able to fill an administrator's queue."""
        recovery_stack.recovery.request_reset("nosuchperson")
        assert recovery_stack.requests.list_requests() == []
        assert AuditAction.PASSWORD_RESET_REQUESTED in recovery_stack.audit_actions()

    def test_inactive_account_queues_nothing(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """A deactivated account is not recovered through this door."""
        recovery_stack.users.set_active(recovery_stack.analyst_id, False)
        assert recovery_stack.recovery.request_reset("analyst") == REQUEST_ACKNOWLEDGEMENT
        assert recovery_stack.requests.list_requests() == []

    def test_a_second_request_does_not_duplicate_the_first(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Clicking twice leaves one row, not two."""
        recovery_stack.recovery.request_reset("analyst")
        recovery_stack.recovery.request_reset("analyst")
        assert len(recovery_stack.requests.list_requests()) == 1

    def test_requests_are_rate_limited_per_account(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Rejecting a request does not open an unlimited retry loop."""
        for _ in range(4):
            recovery_stack.recovery.request_reset("analyst")
            open_request = recovery_stack.requests.open_for_user(
                recovery_stack.analyst_id
            )
            if open_request is not None and open_request.id is not None:
                recovery_stack.recovery.reject(
                    recovery_stack.admin_session, open_request.id, note="test"
                )
        # The policy allows two requests per day; the rest are refused.
        assert len(recovery_stack.requests.list_requests()) == 2


class TestReviewingRequests:
    """Step 2 and 3: only an administrator decides, and it is audited."""

    def test_standard_role_cannot_read_the_queue(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Server-side refusal, regardless of what an interface allows."""
        recovery_stack.recovery.request_reset("analyst")
        with pytest.raises(PermissionDeniedError):
            recovery_stack.recovery.list_requests(recovery_stack.analyst_session)
        with pytest.raises(PermissionDeniedError):
            recovery_stack.recovery.pending_count(recovery_stack.analyst_session)

    def test_standard_role_cannot_approve_or_reject(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The analyst cannot approve their own recovery."""
        recovery_stack.recovery.request_reset("analyst")
        request = recovery_stack.requests.open_for_user(recovery_stack.analyst_id)
        assert request is not None and request.id is not None
        with pytest.raises(PermissionDeniedError):
            recovery_stack.recovery.approve(
                recovery_stack.analyst_session, request.id
            )
        with pytest.raises(PermissionDeniedError):
            recovery_stack.recovery.reject(recovery_stack.analyst_session, request.id)
        assert recovery_stack.requests.get(request.id).status == ResetStatus.PENDING

    def test_refusal_is_audited(self, recovery_stack: RecoveryStack) -> None:
        """An attempt to act beyond a role is itself evidence (§55)."""
        recovery_stack.recovery.request_reset("analyst")
        with pytest.raises(PermissionDeniedError):
            recovery_stack.recovery.list_requests(recovery_stack.analyst_session)
        assert AuditAction.PERMISSION_DENIED in recovery_stack.audit_actions()

    def test_administrator_sees_the_queue(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The pending count and the listing agree."""
        recovery_stack.recovery.request_reset("analyst")
        assert recovery_stack.recovery.pending_count(recovery_stack.admin_session) == 1
        listed = recovery_stack.recovery.list_requests(
            recovery_stack.admin_session, status=ResetStatus.PENDING
        )
        assert [r.username for r in listed] == ["analyst"]

    def test_approval_records_the_reviewer_and_a_deadline(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Who decided, when, and how long the code lives."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        assert code

        request = recovery_stack.requests.approved_for_username("analyst")
        assert request is not None
        assert request.status == ResetStatus.APPROVED
        assert request.reviewer_username == "admin"
        assert request.reviewed_at is not None
        assert request.code_expires_at is not None
        assert AuditAction.PASSWORD_RESET_APPROVED in recovery_stack.audit_actions()

    def test_the_code_is_never_stored_or_logged(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Only its digest is kept, and the audit trail never carries it."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        request = recovery_stack.requests.approved_for_username("analyst")
        assert request is not None and request.id is not None

        stored = recovery_stack.requests.code_hash_for(request.id)
        assert stored == code_fingerprint(code)
        assert code not in stored
        assert code not in recovery_stack.audit_details()
        assert normalise_recovery_code(code) not in recovery_stack.audit_details()

    def test_a_request_cannot_be_approved_twice(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The second administrator is told, not silently given a second code."""
        recovery_stack.recovery.request_reset("analyst")
        request = recovery_stack.requests.open_for_user(recovery_stack.analyst_id)
        assert request is not None and request.id is not None
        recovery_stack.recovery.approve(recovery_stack.admin_session, request.id)
        with pytest.raises(ValidationFailedError):
            recovery_stack.recovery.approve(recovery_stack.admin_session, request.id)

    def test_rejection_is_recorded_and_revokes_the_code(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """A rejected approval stops working immediately."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        request = recovery_stack.requests.approved_for_username("analyst")
        assert request is not None and request.id is not None

        recovery_stack.recovery.reject(
            recovery_stack.admin_session, request.id, note="not who they claimed"
        )
        assert recovery_stack.requests.get(request.id).status == ResetStatus.REJECTED
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        assert AuditAction.PASSWORD_RESET_REJECTED in recovery_stack.audit_actions()

    def test_an_unknown_request_is_refused(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Approving something that is not there fails cleanly."""
        with pytest.raises(ValidationFailedError):
            recovery_stack.recovery.approve(recovery_stack.admin_session, 4242)
        with pytest.raises(ValidationFailedError):
            recovery_stack.recovery.reject(recovery_stack.admin_session, 4242)


class TestRedeemingACode:
    """Step 4: the owner sets their own password, once."""

    def test_the_password_changes_only_after_approval(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """A pending request confers nothing at all."""
        recovery_stack.recovery.request_reset("analyst")
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset(
                "analyst", generate_recovery_code(), NEW_PASSWORD
            )
        assert recovery_stack.authentication.login(
            "analyst", ANALYST_PASSWORD
        ).authenticated

    def test_an_approved_code_sets_the_new_password(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The old password stops working and the new one starts."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)

        with pytest.raises(AuthenticationError):
            recovery_stack.authentication.login("analyst", ANALYST_PASSWORD)
        result = recovery_stack.authentication.login("analyst", NEW_PASSWORD)
        assert result.authenticated
        assert not result.must_change_password

    def test_formatting_of_the_code_does_not_matter(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Lower case and stray spaces still redeem."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        recovery_stack.recovery.complete_reset(
            "analyst", f" {code.lower().replace('-', ' ')} ", NEW_PASSWORD
        )
        assert recovery_stack.authentication.login("analyst", NEW_PASSWORD).authenticated

    def test_a_code_works_exactly_once(self, recovery_stack: RecoveryStack) -> None:
        """Replaying the code cannot change the password a second time."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset(
                "analyst", code, "AnotherOne!2026x"
            )
        assert recovery_stack.authentication.login("analyst", NEW_PASSWORD).authenticated

    def test_a_code_is_bound_to_one_account(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The analyst's code cannot be pointed at the administrator."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset("admin", code, NEW_PASSWORD)
        assert recovery_stack.authentication.login("admin", ADMIN_PASSWORD).authenticated

    def test_wrong_codes_are_counted_then_the_approval_is_revoked(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Guessing is bounded: three wrong codes and the approval is gone."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        request = recovery_stack.requests.approved_for_username("analyst")
        assert request is not None and request.id is not None

        for _ in range(3):
            with pytest.raises(AuthenticationError):
                recovery_stack.recovery.complete_reset(
                    "analyst", "AAAA-BBBB-CCCC-DDDD", NEW_PASSWORD
                )

        assert recovery_stack.requests.get(request.id).status == ResetStatus.REJECTED
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        assert recovery_stack.authentication.login(
            "analyst", ANALYST_PASSWORD
        ).authenticated

    def test_an_expired_approval_is_refused(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The deadline is enforced when the code is presented, not just by a job."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        recovery_stack.db.execute(
            "UPDATE password_reset_requests SET code_expires_at = %s",
            (to_db(utcnow() - timedelta(minutes=1)),),
        )
        with pytest.raises(AuthenticationError):
            recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        assert recovery_stack.authentication.login(
            "analyst", ANALYST_PASSWORD
        ).authenticated

    def test_the_new_password_must_satisfy_policy(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Recovery is not a way around the password rules."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        with pytest.raises(ValidationFailedError):
            recovery_stack.recovery.complete_reset("analyst", code, "short")
        # The approval survives a rejected password, so the operator can retry.
        recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        assert recovery_stack.authentication.login("analyst", NEW_PASSWORD).authenticated

    def test_the_new_password_must_differ_from_the_current_one(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Recovering to the same credential is refused, and says why."""
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        with pytest.raises(ValidationFailedError):
            recovery_stack.recovery.complete_reset("analyst", code, ANALYST_PASSWORD)

    def test_completion_ends_the_account_s_other_sessions(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Whoever was signed in on the old credential is signed out."""
        token = recovery_stack.analyst_session.token
        assert recovery_stack.sessions.get(token) is not None
        recovery_stack.recovery.request_reset("analyst")
        code = _approve_latest(recovery_stack)
        recovery_stack.recovery.complete_reset("analyst", code, NEW_PASSWORD)
        assert recovery_stack.sessions.get(token) is None

    def test_the_whole_workflow_is_audited(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Request, approval and completion each leave a record."""
        recovery_stack.recovery.request_reset("analyst", host_context="WS-014")
        code = _approve_latest(recovery_stack)
        recovery_stack.recovery.complete_reset(
            "analyst", code, NEW_PASSWORD, host_context="WS-014"
        )
        actions = recovery_stack.audit_actions()
        for expected in (
            AuditAction.PASSWORD_RESET_REQUESTED,
            AuditAction.PASSWORD_RESET_APPROVED,
            AuditAction.PASSWORD_RESET_COMPLETED,
        ):
            assert expected in actions


class TestHousekeeping:
    """Deadlines are enforced even when nobody opens the queue."""

    def test_stale_requests_and_approvals_expire(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The background job moves timed-out rows to EXPIRED."""
        recovery_stack.recovery.request_reset("analyst")
        recovery_stack.db.execute(
            "UPDATE password_reset_requests SET expires_at = %s",
            (to_db(utcnow() - timedelta(hours=1)),),
        )
        assert recovery_stack.recovery.expire_stale() == 1
        assert (
            recovery_stack.recovery.pending_count(recovery_stack.admin_session) == 0
        )
        listed = recovery_stack.recovery.list_requests(recovery_stack.admin_session)
        assert listed[0].status == ResetStatus.EXPIRED

    def test_expiring_nothing_is_not_audited(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """A quiet queue produces no noise in the audit trail."""
        before = len(recovery_stack.audit_actions())
        assert recovery_stack.recovery.expire_stale() == 0
        assert len(recovery_stack.audit_actions()) == before


# ---------------------------------------------------------------------------
# Administrator account registration
# ---------------------------------------------------------------------------
class TestAccountRegistration:
    """Step 0: how an operator gets an account in the first place (§70)."""

    def test_administrator_registers_an_account(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The new account exists, holds its role, and can sign in."""
        created = recovery_stack.users_service.create_user(
            recovery_stack.admin_session,
            username="newanalyst", password="Onboard!Pass2026",
            role_name="USER", full_name="New Analyst",
            email="new@example.org",
        )
        assert created.username == "newanalyst"
        assert created.role_name == "USER"
        assert not created.generated

        result = recovery_stack.authentication.login("newanalyst", "Onboard!Pass2026")
        assert result.authenticated
        assert result.must_change_password
        assert result.session is not None
        assert not result.session.has(Permission.USER_MANAGE)

    def test_a_blank_password_is_generated(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Leaving it blank produces a strong credential that actually works."""
        created = recovery_stack.users_service.create_user(
            recovery_stack.admin_session, username="generated", role_name="USER",
        )
        assert created.generated
        assert len(created.password) >= 12
        assert recovery_stack.authentication.login(
            "generated", created.password
        ).authenticated

    def test_a_standard_role_cannot_register_accounts(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Privilege escalation by account creation is refused server-side."""
        with pytest.raises(PermissionDeniedError):
            recovery_stack.users_service.create_user(
                recovery_stack.analyst_session, username="sneaky",
                password="Sneaky!Pass2026", role_name="ADMIN",
            )
        assert recovery_stack.users.get_by_username("sneaky") is None

    def test_duplicate_usernames_are_refused(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """One username, one account."""
        with pytest.raises(ValidationFailedError):
            recovery_stack.users_service.create_user(
                recovery_stack.admin_session, username="analyst",
                password="Another!Pass2026", role_name="USER",
            )

    def test_an_unknown_role_is_refused(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Roles come from the database, not from the caller's imagination."""
        with pytest.raises(ValidationFailedError):
            recovery_stack.users_service.create_user(
                recovery_stack.admin_session, username="wizard",
                password="Wizard!Pass2026", role_name="SUPERUSER",
            )

    def test_a_weak_password_is_refused(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The policy applies to registration too."""
        with pytest.raises(ValidationFailedError):
            recovery_stack.users_service.create_user(
                recovery_stack.admin_session, username="weakling",
                password="password", role_name="USER",
            )

    def test_registration_is_audited(self, recovery_stack: RecoveryStack) -> None:
        """Who created which account, with which role."""
        recovery_stack.users_service.create_user(
            recovery_stack.admin_session, username="audited",
            password="Audited!Pass2026", role_name="USER",
        )
        assert AuditAction.USER_CREATED in recovery_stack.audit_actions()
        assert "audited" in recovery_stack.audit_details()

    def test_the_initial_password_is_never_written_down(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """It is returned once and appears nowhere in storage."""
        created = recovery_stack.users_service.create_user(
            recovery_stack.admin_session, username="quiet", role_name="USER",
        )
        assert created.password not in recovery_stack.audit_details()
        stored_hash, _algorithm = recovery_stack.users.get_password_hash(
            created.user_id
        )
        assert created.password not in stored_hash


class TestRoleChanges:
    """A role change is an authorisation change and is treated as one."""

    def test_role_change_is_audited_separately(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """USER_ROLE_CHANGED names the old and the new role."""
        recovery_stack.users_service.update_user(
            recovery_stack.admin_session, recovery_stack.analyst_id,
            full_name="Analyst", email="analyst@example.org",
            role_name="ADMIN", is_active=True,
        )
        assert AuditAction.USER_ROLE_CHANGED in recovery_stack.audit_actions()
        assert "USER to ADMIN" in recovery_stack.audit_details()

    def test_role_change_ends_the_account_s_sessions(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Permissions are resolved at sign-in, so the old session must go."""
        token = recovery_stack.analyst_session.token
        recovery_stack.users_service.update_user(
            recovery_stack.admin_session, recovery_stack.analyst_id,
            full_name="Analyst", email="", role_name="ADMIN", is_active=True,
        )
        assert recovery_stack.sessions.get(token) is None

    def test_a_profile_edit_that_keeps_the_role_does_not_sign_anyone_out(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """Fixing a typo in a name is not an authorisation event."""
        token = recovery_stack.analyst_session.token
        recovery_stack.users_service.update_user(
            recovery_stack.admin_session, recovery_stack.analyst_id,
            full_name="Analyst Two", email="", role_name="USER", is_active=True,
        )
        assert recovery_stack.sessions.get(token) is not None
        assert AuditAction.USER_ROLE_CHANGED not in recovery_stack.audit_actions()

    def test_the_last_administrator_cannot_be_demoted(
        self, recovery_stack: RecoveryStack
    ) -> None:
        """The installation cannot be locked out of its own administration."""
        admin = recovery_stack.users.get_by_username("admin")
        assert admin is not None and admin.id is not None
        with pytest.raises(ValidationFailedError):
            recovery_stack.users_service.update_user(
                recovery_stack.admin_session, admin.id,
                full_name="Administrator", email="", role_name="USER",
                is_active=True,
            )
