"""Reading a notification is something a person does, not something it becomes.

``notifications.user_id`` is nullable and a NULL means *broadcast* - everyone
can see it. Visibility honoured that from the start: every query filtered on
``user_id IS NULL OR user_id = %s``. Read state did not. ``is_read`` was a
single flag on the shared row, so the first analyst to open the panel marked
the queue read for every other analyst and for the administrator.

The live installation showed how wide that was: all 848 notifications had no
owner, so every one of them was shared state, and 819 were already flagged
read. Among them are the ones ``raise_security_alert`` produces. One person
clearing their panel could hide a standing security alert from the whole team,
and nothing anywhere would say it had happened.

Read state is per reader, so it now lives in its own table. What is pinned
here is the distinction that was missing:

**The notification is the event; the read is the person.** Marking one read
writes a row saying *who* read it and never touches the notification, so the
alert, its level and its timestamp are exactly as raised.

**A dismissal is not a deletion.** Another analyst's panel is unaffected, and
the row survives for everyone who has not read it.

**Nothing is attributed to somebody who did not do it.** The 819 pre-existing
dismissals have no recorded reader - that data was never captured - so they
stay grandfathered on the old column rather than being assigned to whichever
account happened to be convenient.
"""

from __future__ import annotations

import pytest

from aethra_sec.database.repositories.settings import NotificationRepository
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.models.enums import NotificationLevel
from aethra_sec.models.system import Notification
from aethra_sec.security.password import PasswordHashService
from aethra_sec.utils.timeutil import utcnow


def _user(db, username: str) -> int:
    """A real user row, because the read table has a foreign key to one."""
    users = UserRepository(db)
    role = users.get_role_by_name("ADMIN")
    assert role and role.id, "roles are seeded by the migration runner"
    digest = PasswordHashService().hash("AnalystPass!2026")
    return users.create_user(
        username=username,
        password_hash=digest.hash,
        password_algorithm=digest.algorithm,
        role_id=role.id,
        full_name=username.title(),
    )


def _broadcast(repo: NotificationRepository, title: str = "Flood detected") -> int:
    """A notification with no owner - visible to everyone."""
    return repo.create(
        Notification(
            user_id=None,
            level=NotificationLevel.WARNING,
            title=title,
            message="Raised by a detection rule.",
            category="security",
        )
    )


@pytest.fixture
def repo(clean_db) -> NotificationRepository:
    return NotificationRepository(clean_db)


class TestOneReaderDoesNotSpeakForAnother:
    """The defect, stated as a test."""

    def test_a_dismissal_does_not_hide_it_from_anyone_else(
        self, clean_db, repo
    ) -> None:
        alice, bob = _user(clean_db, "alice"), _user(clean_db, "bob")
        notification = _broadcast(repo)

        repo.mark_read(notification, alice)

        assert repo.unread_count(alice) == 0
        assert repo.unread_count(bob) == 1

    def test_mark_all_read_is_scoped_to_the_reader(self, clean_db, repo) -> None:
        alice, bob = _user(clean_db, "alice"), _user(clean_db, "bob")
        for index in range(4):
            _broadcast(repo, f"Detection {index}")

        cleared = repo.mark_all_read(alice)

        assert cleared == 4
        assert repo.unread_count(alice) == 0
        assert repo.unread_count(bob) == 4

    def test_each_reader_sees_their_own_state_in_the_list(
        self, clean_db, repo
    ) -> None:
        alice, bob = _user(clean_db, "alice"), _user(clean_db, "bob")
        notification = _broadcast(repo)
        repo.mark_read(notification, alice)

        for_alice = repo.list_recent(alice, limit=10)
        for_bob = repo.list_recent(bob, limit=10)

        assert [n.is_read for n in for_alice] == [True]
        assert [n.is_read for n in for_bob] == [False]

    def test_unread_only_filters_per_reader(self, clean_db, repo) -> None:
        alice, bob = _user(clean_db, "alice"), _user(clean_db, "bob")
        notification = _broadcast(repo)
        repo.mark_read(notification, alice)

        assert repo.list_recent(alice, unread_only=True, limit=10) == []
        assert len(repo.list_recent(bob, unread_only=True, limit=10)) == 1


class TestTheNotificationItselfIsEvidence:
    """A read is recorded beside the alert, never over it."""

    def test_marking_read_does_not_touch_the_row(self, clean_db, repo) -> None:
        alice = _user(clean_db, "alice")
        notification = _broadcast(repo)
        before = clean_db.query_one(
            "SELECT level, title, message, category, created_at, is_read, read_at "
            "FROM notifications WHERE id = %s",
            (notification,),
        )

        repo.mark_read(notification, alice)

        after = clean_db.query_one(
            "SELECT level, title, message, category, created_at, is_read, read_at "
            "FROM notifications WHERE id = %s",
            (notification,),
        )
        assert after == before

    def test_nothing_is_deleted(self, clean_db, repo) -> None:
        alice = _user(clean_db, "alice")
        _broadcast(repo)
        repo.mark_all_read(alice)

        assert clean_db.query_value("SELECT COUNT(*) FROM notifications") == 1

    def test_the_read_records_who_and_when(self, clean_db, repo) -> None:
        alice = _user(clean_db, "alice")
        notification = _broadcast(repo)

        repo.mark_read(notification, alice)

        row = clean_db.query_one(
            "SELECT user_id, read_at FROM notification_reads "
            "WHERE notification_id = %s",
            (notification,),
        )
        assert row["user_id"] == alice
        assert row["read_at"] is not None


class TestNothingIsAttributedToNobody:
    """A read without a reader is not recorded at all."""

    def test_no_session_writes_no_read(self, clean_db, repo) -> None:
        notification = _broadcast(repo)

        repo.mark_read(notification, None)

        assert clean_db.query_value("SELECT COUNT(*) FROM notification_reads") == 0

    def test_mark_all_read_without_a_reader_is_a_no_op(self, clean_db, repo) -> None:
        _broadcast(repo)

        assert repo.mark_all_read(None) == 0
        assert clean_db.query_value("SELECT COUNT(*) FROM notification_reads") == 0

    def test_pre_existing_dismissals_stay_grandfathered(self, clean_db, repo) -> None:
        """No data says who dismissed them, so nobody is named.

        They still count as read - they were - but on the old column, not as
        an invented per-user attribution.
        """
        alice = _user(clean_db, "alice")
        notification = _broadcast(repo)
        clean_db.execute(
            "UPDATE notifications SET is_read = 1, read_at = %s WHERE id = %s",
            (utcnow(), notification),
        )

        assert repo.unread_count(alice) == 0
        assert clean_db.query_value("SELECT COUNT(*) FROM notification_reads") == 0


class TestTargetedNotificationsStillWork:
    """The owner-scoped case must not have regressed."""

    def test_only_the_addressee_sees_it(self, clean_db, repo) -> None:
        alice, bob = _user(clean_db, "alice"), _user(clean_db, "bob")
        repo.create(
            Notification(
                user_id=alice, level=NotificationLevel.INFO,
                title="Your scan finished", message="", category="scan",
            )
        )

        assert repo.unread_count(alice) == 1
        assert repo.unread_count(bob) == 0
        assert repo.list_recent(bob, limit=10) == []


class TestRepeatedReadsAreHarmless:
    """The panel refreshes; the same read arrives more than once."""

    def test_marking_read_twice_is_idempotent(self, clean_db, repo) -> None:
        alice = _user(clean_db, "alice")
        notification = _broadcast(repo)

        repo.mark_read(notification, alice)
        first = clean_db.query_value(
            "SELECT read_at FROM notification_reads WHERE notification_id = %s",
            (notification,),
        )
        repo.mark_read(notification, alice)
        second = clean_db.query_value(
            "SELECT read_at FROM notification_reads WHERE notification_id = %s",
            (notification,),
        )

        assert first == second
        assert clean_db.query_value("SELECT COUNT(*) FROM notification_reads") == 1

    def test_mark_all_read_twice_reports_nothing_the_second_time(
        self, clean_db, repo
    ) -> None:
        alice = _user(clean_db, "alice")
        _broadcast(repo)

        assert repo.mark_all_read(alice) == 1
        assert repo.mark_all_read(alice) == 0


class TestDeletingANotificationCleansUpAfterItself:
    """Read rows must not outlive what they refer to."""

    def test_reads_are_cascaded(self, clean_db, repo) -> None:
        alice = _user(clean_db, "alice")
        notification = _broadcast(repo)
        repo.mark_read(notification, alice)

        clean_db.execute("DELETE FROM notifications WHERE id = %s", (notification,))

        assert clean_db.query_value("SELECT COUNT(*) FROM notification_reads") == 0
