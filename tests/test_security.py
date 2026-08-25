"""Password hashing, audit integrity, RBAC and the event bus.

These tests run without a database except where a repository is genuinely
required; the database-backed authentication tests live in
``test_database.py``.
"""

from __future__ import annotations

import pytest

from aethra_sec.core.errors import PermissionDeniedError, SessionExpiredError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType
from aethra_sec.core.permissions import (
    ADMIN_PERMISSIONS,
    USER_PERMISSIONS,
    Permission,
    PermissionSet,
)
from aethra_sec.core.session import SessionManager
from aethra_sec.security.integrity import (
    GENESIS_HASH,
    compute_hash,
    verify_chain,
)
from aethra_sec.security.password import (
    PasswordHashService,
    generate_temporary_password,
    token_fingerprint,
)
from aethra_sec.security.rbac import AccessControl
from aethra_sec.models.user import AuditRecord
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import validate_password


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
class TestPasswordHashing:
    """Credentials are hashed, never stored or compared as text."""

    def test_hash_is_not_the_password(self) -> None:
        """The stored value never contains the plaintext."""
        service = PasswordHashService()
        result = service.hash("CorrectHorse!2026")
        assert "CorrectHorse!2026" not in result.hash
        assert len(result.hash) > 20

    def test_verification(self) -> None:
        """The right password verifies and the wrong one does not."""
        service = PasswordHashService()
        stored = service.hash("CorrectHorse!2026").hash
        assert service.verify("CorrectHorse!2026", stored)
        assert not service.verify("correcthorse!2026", stored)
        assert not service.verify("", stored)

    def test_salting_makes_hashes_unique(self) -> None:
        """The same password hashes differently every time."""
        service = PasswordHashService()
        first = service.hash("CorrectHorse!2026").hash
        second = service.hash("CorrectHorse!2026").hash
        assert first != second
        assert service.verify("CorrectHorse!2026", first)
        assert service.verify("CorrectHorse!2026", second)

    def test_pbkdf2_fallback_round_trip(self) -> None:
        """The fallback algorithm works on its own."""
        service = PasswordHashService(prefer_argon2=False)
        assert service.algorithm == "pbkdf2_sha256"
        stored = service.hash("CorrectHorse!2026").hash
        assert stored.startswith("pbkdf2_sha256$")
        assert service.verify("CorrectHorse!2026", stored)
        assert not service.verify("wrong", stored)

    def test_cross_algorithm_verification(self) -> None:
        """An Argon2-capable install can still verify PBKDF2 credentials."""
        fallback = PasswordHashService(prefer_argon2=False)
        preferred = PasswordHashService()
        stored = fallback.hash("CorrectHorse!2026").hash
        assert preferred.verify("CorrectHorse!2026", stored)

    def test_rehash_is_requested_for_weaker_credentials(self) -> None:
        """A PBKDF2 credential is flagged for upgrade where Argon2 exists."""
        preferred = PasswordHashService()
        if preferred.algorithm != "argon2id":
            pytest.skip("argon2-cffi is not installed in this environment.")
        legacy = PasswordHashService(prefer_argon2=False).hash("CorrectHorse!2026").hash
        assert preferred.needs_rehash(legacy)
        assert not preferred.needs_rehash(preferred.hash("CorrectHorse!2026").hash)

    def test_malformed_hash_fails_closed(self) -> None:
        """An unrecognised stored value verifies as false, never true."""
        service = PasswordHashService()
        for bad in ("", "not-a-hash", "pbkdf2_sha256$broken", "$argon2id$bad"):
            assert not service.verify("anything", bad)

    def test_generated_password_meets_policy(self) -> None:
        """A generated reset password always satisfies the policy."""
        for _ in range(20):
            assert validate_password(generate_temporary_password(), min_length=12)

    def test_token_fingerprint_is_stable_and_opaque(self) -> None:
        """Sessions are stored by fingerprint, never by token."""
        token = "example-session-token"
        digest = token_fingerprint(token)
        assert digest == token_fingerprint(token)
        assert token not in digest
        assert len(digest) == 64


# ---------------------------------------------------------------------------
# Audit integrity
# ---------------------------------------------------------------------------
def _record(record_id: int, action: str, detail: str = "") -> AuditRecord:
    """Build an audit record for chain tests."""
    return AuditRecord(
        id=record_id,
        occurred_at=utcnow(),
        user_id=1,
        username="admin",
        action=action,
        category="test",
        target_type="thing",
        target_id=str(record_id),
        result="SUCCESS",
        detail=detail,
        host_context="lab-host",
        source="SYSTEM",
    )


def _chain(count: int) -> list[AuditRecord]:
    """Build a valid hash chain of ``count`` records."""
    records: list[AuditRecord] = []
    previous = GENESIS_HASH
    for index in range(1, count + 1):
        record = _record(index, f"ACTION_{index}")
        record.previous_hash = previous
        record.record_hash = compute_hash(record, previous)
        previous = record.record_hash
        records.append(record)
    return records


class TestAuditIntegrity:
    """A modified, removed or re-ordered record must be detectable (§56)."""

    def test_valid_chain(self) -> None:
        """An untouched chain verifies cleanly."""
        report = verify_chain(_chain(10))
        assert report.is_valid
        assert report.checked == 10
        assert "LOG INTEGRITY OK" in report.summary

    def test_modified_record_is_detected(self) -> None:
        """Editing a record's content breaks its own hash."""
        records = _chain(10)
        records[4].detail = "quietly edited"
        report = verify_chain(records)
        assert not report.is_valid
        assert any(issue.kind == "CONTENT" for issue in report.issues)
        assert "LOG INTEGRITY WARNING" in report.summary

    def test_removed_record_is_detected(self) -> None:
        """Deleting a record breaks the link at the following record."""
        records = _chain(10)
        del records[5]
        report = verify_chain(records)
        assert not report.is_valid
        assert any(issue.kind == "CHAIN" for issue in report.issues)

    def test_reordering_is_detected(self) -> None:
        """Swapping two records is detected."""
        records = _chain(10)
        records[3], records[4] = records[4], records[3]
        report = verify_chain(records)
        assert not report.is_valid

    def test_inserted_record_is_detected(self) -> None:
        """A forged record inserted mid-chain is detected."""
        records = _chain(10)
        forged = _record(999, "FORGED_ENTRY")
        forged.previous_hash = records[4].record_hash
        forged.record_hash = compute_hash(forged, forged.previous_hash)
        records.insert(5, forged)
        report = verify_chain(records)
        assert not report.is_valid

    def test_field_changes_are_all_covered(self) -> None:
        """Every audited field participates in the hash."""
        base = _record(1, "ACTION")
        base.previous_hash = GENESIS_HASH
        original = compute_hash(base, GENESIS_HASH)
        for attribute, value in (
            ("username", "someone-else"),
            ("action", "DIFFERENT"),
            ("result", "FAILURE"),
            ("detail", "changed"),
            ("target_id", "99"),
            ("host_context", "other-host"),
        ):
            mutated = _record(1, "ACTION")
            mutated.occurred_at = base.occurred_at
            setattr(mutated, attribute, value)
            assert compute_hash(mutated, GENESIS_HASH) != original, attribute

    def test_unhashed_records_are_reported_separately(self) -> None:
        """Records predating hashing are counted, not called tampering."""
        records = _chain(3)
        for record in records:
            record.record_hash = ""
            record.previous_hash = ""
        report = verify_chain(records)
        assert report.is_valid
        assert report.unhashed == 3

    def test_empty_log(self) -> None:
        """An empty log verifies with an explicit message."""
        report = verify_chain([])
        assert report.is_valid
        assert "No audit records" in report.summary


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------
class TestRoleBasedAccessControl:
    """Permissions are enforced at the service layer (§8, §55)."""

    @staticmethod
    def _session(manager: SessionManager, role: str):
        """Create a session with a role's default permissions."""
        return manager.create(
            user_id=1 if role == "ADMIN" else 2,
            username=role.lower(),
            role=role,
            permissions=PermissionSet.for_role(role),
        )

    def test_role_definitions(self) -> None:
        """ADMIN holds everything; USER holds a restricted subset."""
        admin = PermissionSet.for_role("ADMIN")
        user = PermissionSet.for_role("USER")
        assert admin.codes == set(ADMIN_PERMISSIONS)
        assert user.codes == set(USER_PERMISSIONS)
        assert user.codes < admin.codes

    @pytest.mark.parametrize(
        "permission",
        [
            Permission.USER_MANAGE,
            Permission.SETTINGS_MANAGE,
            Permission.LOG_VIEW,
            Permission.LOG_VERIFY,
            Permission.MITIGATION_MANAGE,
            Permission.DATA_MAINTAIN,
            Permission.HEALTH_DETAIL,
        ],
    )
    def test_administrative_permissions_withheld_from_users(self, permission: str) -> None:
        """A normal user never holds an administrative permission."""
        assert not PermissionSet.for_role("USER").has(permission)
        assert PermissionSet.for_role("ADMIN").has(permission)

    @pytest.mark.parametrize(
        "permission",
        [
            Permission.DASHBOARD_VIEW,
            Permission.MONITOR_VIEW,
            Permission.MONITOR_CONTROL,
            Permission.SCAN_RUN,
            Permission.ALERT_VIEW,
            Permission.INCIDENT_VIEW,
            Permission.MITIGATION_VIEW,
            Permission.REPORT_GENERATE,
        ],
    )
    def test_analyst_permissions_granted(self, permission: str) -> None:
        """A normal user holds the analyst permissions the spec lists (§8)."""
        assert PermissionSet.for_role("USER").has(permission)

    def test_require_refuses_missing_permission(self) -> None:
        """A refused action raises rather than proceeding."""
        manager = SessionManager()
        access = AccessControl(manager)
        user = self._session(manager, "USER")
        with pytest.raises(PermissionDeniedError):
            access.require(user, Permission.USER_MANAGE)

    def test_require_allows_granted_permission(self) -> None:
        """A granted action returns the live session."""
        manager = SessionManager()
        access = AccessControl(manager)
        admin = self._session(manager, "ADMIN")
        assert access.require(admin, Permission.USER_MANAGE).username == "admin"

    def test_require_admin(self) -> None:
        """The admin-role gate refuses a normal user."""
        manager = SessionManager()
        access = AccessControl(manager)
        assert access.require_admin(self._session(manager, "ADMIN"))
        with pytest.raises(PermissionDeniedError):
            access.require_admin(self._session(manager, "USER"))

    def test_expired_session_is_refused(self) -> None:
        """An invalidated session cannot act."""
        manager = SessionManager()
        access = AccessControl(manager)
        session = self._session(manager, "ADMIN")
        manager.invalidate(session.token)
        with pytest.raises(SessionExpiredError):
            access.require(session, Permission.DASHBOARD_VIEW)

    def test_navigation_is_filtered_by_role(self) -> None:
        """The sidebar reflects the role, and the admin sees strictly more."""
        manager = SessionManager()
        access = AccessControl(manager)
        admin_nav = access.visible_navigation(self._session(manager, "ADMIN"))
        user_nav = access.visible_navigation(self._session(manager, "USER"))
        assert "Users" in admin_nav
        assert "Settings" in admin_nav
        assert "Logs & Audit" in admin_nav
        assert "Users" not in user_nav
        assert "Settings" not in user_nav
        assert "Logs & Audit" not in user_nav
        assert "Dashboard" in user_nav

    def test_permission_denied_message_is_generic(self) -> None:
        """The operator sees a generic message; the code goes to the log."""
        error = PermissionDeniedError(Permission.USER_MANAGE)
        assert error.permission == Permission.USER_MANAGE
        assert "do not have permission" in error.user_message


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class TestSessionManager:
    """Session lifecycle and administrative termination."""

    def test_tokens_are_unique_and_opaque(self) -> None:
        """Session tokens are random, not derived from user data."""
        manager = SessionManager()
        tokens = {
            manager.create(
                user_id=1, username="admin", role="ADMIN",
                permissions=PermissionSet.for_role("ADMIN"),
            ).token
            for _ in range(50)
        }
        assert len(tokens) == 50
        assert all("admin" not in token for token in tokens)

    def test_expiry_removes_the_session(self) -> None:
        """An expired session stops resolving."""
        from datetime import timedelta

        manager = SessionManager(timeout_minutes=60)
        session = manager.create(
            user_id=1, username="admin", role="ADMIN",
            permissions=PermissionSet.for_role("ADMIN"),
        )
        session.expires_at = utcnow() - timedelta(seconds=1)
        assert manager.get(session.token) is None

    def test_invalidate_user_terminates_every_session(self) -> None:
        """Force-logout removes all of one user's sessions."""
        manager = SessionManager()
        for _ in range(3):
            manager.create(
                user_id=7, username="analyst", role="USER",
                permissions=PermissionSet.for_role("USER"),
            )
        manager.create(
            user_id=8, username="other", role="USER",
            permissions=PermissionSet.for_role("USER"),
        )
        assert len(manager.invalidate_user(7)) == 3
        assert manager.count() == 1


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------
class TestEventBus:
    """The bus must never block a producer or break on a bad subscriber."""

    def test_queued_delivery(self) -> None:
        """Queued subscribers receive events when drained."""
        bus = EventBus()
        received: list[str] = []
        subscription = bus.subscribe(
            EventType.SNORT_ALERT_RECEIVED, lambda event: received.append(event.type)
        )
        bus.publish(EventType.SNORT_ALERT_RECEIVED, "payload")
        assert received == []
        assert bus.dispatch(subscription) == 1
        assert received == [EventType.SNORT_ALERT_RECEIVED]

    def test_inline_delivery(self) -> None:
        """Inline subscribers receive events immediately."""
        bus = EventBus()
        received: list[object] = []
        bus.subscribe(
            EventType.CAPTURE_STARTED, lambda event: received.append(event.payload),
            queued=False,
        )
        bus.publish(EventType.CAPTURE_STARTED, "started")
        assert received == ["started"]

    def test_bounded_queue_drops_oldest_and_counts(self) -> None:
        """Overflow is bounded and visible, never unbounded growth (§105)."""
        bus = EventBus()
        subscription = bus.subscribe(
            EventType.PACKET_BATCH_PROCESSED, lambda _e: None, max_size=16
        )
        for index in range(200):
            bus.publish(EventType.PACKET_BATCH_PROCESSED, index)
        assert bus.pending(subscription) == 16
        assert bus.statistics()["dropped_events"] == 184

    def test_failing_subscriber_does_not_break_the_bus(self) -> None:
        """One broken subscriber cannot stop the others."""
        bus = EventBus()
        healthy: list[int] = []

        def broken(_event: object) -> None:
            raise RuntimeError("subscriber failure")

        bus.subscribe(EventType.SYSTEM_ERROR, broken, queued=False)
        bus.subscribe(
            EventType.SYSTEM_ERROR, lambda _e: healthy.append(1), queued=False
        )
        bus.publish(EventType.SYSTEM_ERROR, "boom")
        assert healthy == [1]
        assert bus.statistics()["subscriber_errors"] == 1

    def test_unsubscribe(self) -> None:
        """An unsubscribed consumer stops receiving events."""
        bus = EventBus()
        received: list[int] = []
        subscription = bus.subscribe(
            EventType.INCIDENT_CREATED, lambda _e: received.append(1)
        )
        bus.unsubscribe(subscription)
        bus.publish(EventType.INCIDENT_CREATED, None)
        assert bus.dispatch_all() == 0
        assert received == []

    def test_publishing_with_no_subscribers_is_safe(self) -> None:
        """Publishing into the void is a no-op."""
        bus = EventBus()
        bus.publish(EventType.NMAP_SCAN_COMPLETED, None)
        assert bus.statistics()["published"] == 1
