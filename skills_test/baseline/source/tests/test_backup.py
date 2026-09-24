"""Database backup: the schedule, the folder, and what may be deleted.

The dump itself is ``mysqldump``, and is exercised against a real server by the
integration suite. What is pinned here is everything around it, because that is
where a backup feature quietly goes wrong:

* the schedule is measured from the newest backup on disk, so a restart does
  not push the next backup back, and an installation that has never taken one
  is due immediately;
* automatic backup is off until somebody turns it on;
* pruning deletes only files this service wrote, never the newest one, and
  never anything when the keep count is zero;
* a name handed in from the interface cannot reach a file outside the backup
  folder;
* a scheduled run that fails is recorded as a failure and reported, not
  swallowed.

Synthetic fixtures live only in this suite (§99): the files below are written
by the tests themselves, and nothing here is importable by the application.
"""

from __future__ import annotations

from datetime import timedelta
import re
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.config.defaults import BACKUP_SETTINGS, SETTING_SPEC_BY_KEY
from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.services.backup_service import (
    BACKUP_PREFIX,
    BACKUP_SUFFIX,
    BackupService,
    BackupStatus,
)
from aethra_sec.utils.timeutil import utcnow


class _Settings:
    """The handful of setting reads the service makes."""

    def __init__(self, **values: Any) -> None:
        self._values = {spec.key: spec.default for spec in BACKUP_SETTINGS}
        self._values.update(values)

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._values.get(key, default))

    def get_str(self, key: str, default: str = "") -> str:
        return str(self._values.get(key, default))

    def set_value(self, key: str, value: Any) -> None:
        self._values[key] = value


class _Audit:
    """Records what would have been written to the audit trail."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, action: str, **fields: Any) -> None:
        self.entries.append({"action": action, **fields})


class _Access:
    """Grants every check, and remembers that it was asked."""

    def __init__(self) -> None:
        self.checks: list[str] = []

    def require(self, session: Any, permission: str, target: str = "") -> Any:
        self.checks.append(str(permission))
        return session


class _Bus:
    """Collects published events."""

    def __init__(self) -> None:
        self.published: list[tuple[str, Any]] = []

    def publish(self, event_type: str, payload: Any = None) -> None:
        self.published.append((event_type, payload))


class _Db:
    """Only ``settings`` is read, for the connection details."""

    class settings:  # noqa: N801 - mirrors the attribute the service reads
        host = "127.0.0.1"
        port = 3306
        user = "aethra"
        password = "not-a-real-password"
        database = "aethra_sec_test"


def _service(tmp_path: Path, **overrides: Any) -> tuple[BackupService, _Settings]:
    """A service writing into ``tmp_path``."""
    settings = _Settings(**overrides)
    service = BackupService(
        _Db(), settings, _Audit(), _Access(), tmp_path, _Bus()  # type: ignore[arg-type]
    )
    return service, settings


def _write_backup(directory: Path, name: str, *, age_hours: float = 0.0) -> Path:
    """Create a file the service will recognise as one of its backups."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{BACKUP_PREFIX}{name}{BACKUP_SUFFIX}"
    path.write_text("-- dump\n", encoding="utf-8")
    if age_hours:
        stamp = (utcnow() - timedelta(hours=age_hours)).timestamp()
        import os

        os.utime(path, (stamp, stamp))
    return path


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class TestBackupSettings:
    """The schedule is configuration, not a constant in the code."""

    def test_every_knob_is_a_declared_setting(self) -> None:
        """So it appears in the Settings table and survives an upgrade."""
        for key in (
            "backup.automatic_enabled",
            "backup.interval_hours",
            "backup.directory",
            "backup.keep_files",
        ):
            assert key in SETTING_SPEC_BY_KEY

    def test_automatic_backup_is_off_until_asked_for(self) -> None:
        """A job that writes the whole database to disk is opt-in."""
        assert SETTING_SPEC_BY_KEY["backup.automatic_enabled"].default is False

    def test_the_interval_cannot_be_set_to_zero(self) -> None:
        """A zero interval would mean a backup every tick."""
        assert SETTING_SPEC_BY_KEY["backup.interval_hours"].minimum == 1


# ---------------------------------------------------------------------------
# The timer
# ---------------------------------------------------------------------------
class TestSchedule:
    """When the next automatic backup falls."""

    def test_a_schedule_that_is_off_is_never_due(self, tmp_path: Path) -> None:
        """Nothing runs until an administrator turns it on."""
        service, _ = _service(tmp_path)
        status = service.status()
        assert status.automatic_enabled is False
        assert status.due_at is None
        assert status.is_due is False

    def test_an_installation_with_no_backup_is_due_immediately(
        self, tmp_path: Path
    ) -> None:
        """Turning the schedule on should produce a backup, not a wait."""
        service, _ = _service(tmp_path, **{"backup.automatic_enabled": True})
        assert service.status().is_due is True

    def test_the_countdown_runs_from_the_newest_backup(self, tmp_path: Path) -> None:
        """Not from process start, so a restart does not delay the next one."""
        _write_backup(tmp_path, "old", age_hours=30)
        _write_backup(tmp_path, "recent", age_hours=1)
        service, _ = _service(
            tmp_path,
            **{"backup.automatic_enabled": True, "backup.interval_hours": 24},
        )
        status = service.status()
        assert status.latest is not None
        assert status.latest.name.endswith(f"recent{BACKUP_SUFFIX}")
        assert status.is_due is False

    def test_a_backup_older_than_the_interval_is_due(self, tmp_path: Path) -> None:
        """The interval means 'never longer than this without a backup'."""
        _write_backup(tmp_path, "stale", age_hours=25)
        service, _ = _service(
            tmp_path,
            **{"backup.automatic_enabled": True, "backup.interval_hours": 24},
        )
        assert service.status().is_due is True

    def test_the_due_time_is_the_newest_backup_plus_the_interval(
        self, tmp_path: Path
    ) -> None:
        """So the interface can say when, not just whether."""
        _write_backup(tmp_path, "recent", age_hours=2)
        service, _ = _service(
            tmp_path,
            **{"backup.automatic_enabled": True, "backup.interval_hours": 6},
        )
        status = service.status()
        assert status.latest is not None
        assert status.due_at == status.latest.created_at + timedelta(hours=6)

    def test_a_scheduled_run_that_is_not_due_does_nothing(
        self, tmp_path: Path
    ) -> None:
        """The job ticks every minute; it must not dump every minute."""
        _write_backup(tmp_path, "recent", age_hours=1)
        service, _ = _service(
            tmp_path,
            **{"backup.automatic_enabled": True, "backup.interval_hours": 24},
        )
        assert service.run_scheduled() is None

    def test_a_missing_tool_is_reported_rather_than_retried_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator who thinks backups are running must be told they are not."""
        service, _ = _service(tmp_path, **{"backup.automatic_enabled": True})
        monkeypatch.setattr(
            BackupService, "tool_path", property(lambda self: ""), raising=True
        )
        assert service.run_scheduled() is None
        assert "mysqldump" in service.status().last_error
        audit = service._audit  # noqa: SLF001 - asserting the recorded outcome
        assert audit.entries[-1]["result"] == "FAILURE"
        assert service._bus.published  # noqa: SLF001 - the operator is notified


# ---------------------------------------------------------------------------
# The folder
# ---------------------------------------------------------------------------
class TestListing:
    """What counts as a backup, and what does not."""

    def test_only_files_this_service_wrote_are_listed(self, tmp_path: Path) -> None:
        """Somebody else's file in the folder is not a backup."""
        _write_backup(tmp_path, "one")
        (tmp_path / "notes.txt").write_text("mine", encoding="utf-8")
        (tmp_path / "database.sql").write_text("someone else's", encoding="utf-8")
        service, _ = _service(tmp_path)
        assert [item.name for item in service.list_backups()] == [
            f"{BACKUP_PREFIX}one{BACKUP_SUFFIX}"
        ]

    def test_backups_are_listed_newest_first(self, tmp_path: Path) -> None:
        """The list answers "when did we last back up?" at a glance."""
        _write_backup(tmp_path, "older", age_hours=10)
        _write_backup(tmp_path, "newer", age_hours=1)
        service, _ = _service(tmp_path)
        assert [item.name for item in service.list_backups()] == [
            f"{BACKUP_PREFIX}newer{BACKUP_SUFFIX}",
            f"{BACKUP_PREFIX}older{BACKUP_SUFFIX}",
        ]

    def test_a_missing_folder_is_not_an_error(self, tmp_path: Path) -> None:
        """Before the first backup there is nothing to read."""
        service, _ = _service(tmp_path / "not-created-yet")
        assert service.list_backups() == []

    def test_the_configured_folder_overrides_the_default(
        self, tmp_path: Path
    ) -> None:
        """An administrator can put backups on another disk."""
        elsewhere = tmp_path / "elsewhere"
        service, _ = _service(tmp_path, **{"backup.directory": str(elsewhere)})
        assert service.directory == elsewhere


# ---------------------------------------------------------------------------
# Deleting
# ---------------------------------------------------------------------------
class TestPruning:
    """Deleting old backups is the one destructive thing here."""

    def test_nothing_is_deleted_when_every_file_is_kept(
        self, tmp_path: Path
    ) -> None:
        """Zero means keep everything, not keep nothing."""
        for index in range(4):
            _write_backup(tmp_path, f"b{index}", age_hours=index)
        service, _ = _service(tmp_path, **{"backup.keep_files": 0})
        assert service.prune() == 0
        assert len(service.list_backups()) == 4

    def test_the_oldest_beyond_the_keep_count_are_removed(
        self, tmp_path: Path
    ) -> None:
        """And the survivors are the newest ones."""
        for index in range(5):
            _write_backup(tmp_path, f"b{index}", age_hours=index)
        service, _ = _service(tmp_path, **{"backup.keep_files": 2})
        assert service.prune() == 3
        assert [item.name for item in service.list_backups()] == [
            f"{BACKUP_PREFIX}b0{BACKUP_SUFFIX}",
            f"{BACKUP_PREFIX}b1{BACKUP_SUFFIX}",
        ]

    def test_the_newest_backup_is_never_pruned(self, tmp_path: Path) -> None:
        """Whatever the setting says, the last copy stays."""
        _write_backup(tmp_path, "only", age_hours=99)
        service, settings = _service(tmp_path)
        settings.set_value("backup.keep_files", 1)
        service.prune()
        assert len(service.list_backups()) == 1

    def test_pruning_never_touches_a_file_it_did_not_write(
        self, tmp_path: Path
    ) -> None:
        """The folder may hold other things; they are not ours to delete."""
        for index in range(3):
            _write_backup(tmp_path, f"b{index}", age_hours=index + 1)
        bystander = tmp_path / "important-notes.txt"
        bystander.write_text("keep me", encoding="utf-8")
        service, _ = _service(tmp_path, **{"backup.keep_files": 1})
        service.prune()
        assert bystander.exists()


class TestGeneratedNames:
    """Two backups in the same second must both survive."""

    def test_a_free_name_is_used_as_is(self, tmp_path: Path) -> None:
        """The ordinary case stays a plain timestamp."""
        service, _ = _service(tmp_path)
        name = service._generated_name("db").name  # noqa: SLF001
        assert name.startswith(f"{BACKUP_PREFIX}db_")
        assert name.endswith(BACKUP_SUFFIX)
        # No collision counter: the stem is exactly date_time. Substring checks
        # cannot express this - a 20:04:45 backup is stamped 20260901_200445,
        # whose time half legitimately contains "_2".
        stem = name.removeprefix(f"{BACKUP_PREFIX}db_").removesuffix(BACKUP_SUFFIX)
        assert re.fullmatch(r"\d{8}_\d{6}", stem), stem

    def test_a_taken_name_takes_a_counter_rather_than_failing(
        self, tmp_path: Path
    ) -> None:
        """A scheduled run must not fail because a manual one just ran.

        The stamp is only accurate to the second: a manual backup followed
        immediately by a scheduled one produced the same name, and the
        scheduled run died reporting the file already existed.
        """
        service, _ = _service(tmp_path)
        first = service._generated_name("db")  # noqa: SLF001
        first.parent.mkdir(parents=True, exist_ok=True)
        first.write_text("-- taken\n", encoding="utf-8")
        second = service._generated_name("db")  # noqa: SLF001
        assert second != first
        assert not second.exists()

    def test_the_existing_backup_is_never_overwritten(self, tmp_path: Path) -> None:
        """Which is the whole point of picking a new name."""
        service, _ = _service(tmp_path)
        first = service._generated_name("db")  # noqa: SLF001
        first.parent.mkdir(parents=True, exist_ok=True)
        first.write_text("-- original\n", encoding="utf-8")
        service._generated_name("db")  # noqa: SLF001
        assert first.read_text(encoding="utf-8") == "-- original\n"


class TestNameResolution:
    """A name arriving from the interface is not trusted."""

    @pytest.mark.parametrize(
        "name",
        ["../outside.sql", "/etc/passwd", "notes.txt", "does-not-exist.sql"],
    )
    def test_a_name_outside_the_folder_is_refused(
        self, tmp_path: Path, name: str
    ) -> None:
        """Traversal, absolute paths and non-backups are all rejected."""
        _write_backup(tmp_path, "real")
        (tmp_path.parent / "outside.sql").write_text("x", encoding="utf-8")
        service, _ = _service(tmp_path)
        with pytest.raises(ValidationFailedError):
            service.delete(object(), name)

    def test_a_real_backup_resolves_and_is_deleted(self, tmp_path: Path) -> None:
        """The ordinary case still works, and is audited."""
        path = _write_backup(tmp_path, "real")
        service, _ = _service(tmp_path)
        service.delete(object(), path.name)
        assert not path.exists()
        audit = service._audit  # noqa: SLF001 - asserting the recorded outcome
        assert audit.entries[-1]["target_id"] == path.name

    def test_deleting_requires_the_maintenance_permission(
        self, tmp_path: Path
    ) -> None:
        """The interface hides the button; this layer is the control."""
        path = _write_backup(tmp_path, "real")
        service, _ = _service(tmp_path)
        service.delete(object(), path.name)
        access = service._access  # noqa: SLF001 - asserting the check happened
        assert "data.maintain" in access.checks


class TestSaveCopy:
    """Saving a copy is how a backup leaves the machine."""

    def test_a_copy_lands_where_the_operator_asked(self, tmp_path: Path) -> None:
        """Including into a folder that does not exist yet."""
        source = _write_backup(tmp_path / "backups", "real")
        service, _ = _service(tmp_path / "backups")
        target = tmp_path / "usb" / "copy.sql"
        assert service.save_copy(object(), source.name, target) == target
        assert target.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")

    def test_the_original_is_left_alone(self, tmp_path: Path) -> None:
        """A copy is a copy - it is not a move."""
        source = _write_backup(tmp_path / "backups", "real")
        service, _ = _service(tmp_path / "backups")
        service.save_copy(object(), source.name, tmp_path / "copy.sql")
        assert source.exists()

    def test_copying_is_audited(self, tmp_path: Path) -> None:
        """A backup leaving the machine is worth a record."""
        source = _write_backup(tmp_path / "backups", "real")
        service, _ = _service(tmp_path / "backups")
        service.save_copy(object(), source.name, tmp_path / "copy.sql")
        audit = service._audit  # noqa: SLF001 - asserting the recorded outcome
        assert "copied to" in audit.entries[-1]["detail"]


class TestStatusReporting:
    """What the interface is given to display."""

    def test_the_totals_are_measured_not_estimated(self, tmp_path: Path) -> None:
        """Every figure comes from a file that exists."""
        for index in range(3):
            _write_backup(tmp_path, f"b{index}", age_hours=index)
        service, _ = _service(tmp_path)
        status = service.status()
        assert len(status.backups) == 3
        assert status.total_bytes == sum(
            item.path.stat().st_size for item in status.backups
        )

    def test_an_empty_installation_reports_no_backup(self, tmp_path: Path) -> None:
        """Not a zero that could be mistaken for a backup of nothing."""
        status = _service(tmp_path)[0].status()
        assert status.latest is None
        assert status.backups == []

    def test_status_is_a_plain_snapshot(self, tmp_path: Path) -> None:
        """The screen renders it without calling back into the service."""
        assert isinstance(_service(tmp_path)[0].status(), BackupStatus)
