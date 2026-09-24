"""Database backup: on demand, on a schedule, and saved where you want it.

Three things an operator asks of a backup feature, and all three are here:

* **make one now** - a real ``mysqldump`` of the live schema, written to a
  timestamped file that never overwrites an existing one;
* **save a copy** - the same dump written to a location the operator chose, so
  a backup can leave the machine without anyone hunting for the folder;
* **make one by itself** - a scheduled run that fires once the configured
  interval has elapsed.

The countdown is measured from the newest backup already on disk rather than
from a timer in memory. That is deliberate: a restart, a crash or an upgrade
does not silently reset the schedule, and the interval means what it says -
"never more than this long without a backup" - rather than "this long after
the last time the process happened to start".

Nothing here invents a backup. Every figure the interface shows - the file
list, the sizes, the times, the next due time - is read from files that exist
on disk, and a backup that fails is reported as a failure rather than logged
as a success (§111).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType, NotificationPayload
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.models.enums import NotificationLevel
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import safe_filename

LOGGER = get_logger("services.backup")

#: Filename prefix every backup this service writes carries. Pruning and the
#: file listing both match on it, so nothing else in the folder is ever
#: touched - not a note, not an unrelated dump, not a subdirectory.
BACKUP_PREFIX = "aethra_backup_"

#: Extension of a backup file.
BACKUP_SUFFIX = ".sql"

#: Longest a dump may run before it is abandoned, in seconds.
DUMP_TIMEOUT = 1800


@dataclass(frozen=True)
class BackupFile:
    """One backup that exists on disk."""

    path: Path
    size_bytes: int
    created_at: datetime

    @property
    def name(self) -> str:
        """The file's name."""
        return self.path.name


@dataclass
class BackupStatus:
    """What the interface needs to describe the backup arrangement."""

    directory: Path
    automatic_enabled: bool
    interval_hours: int
    keep_files: int
    tool_available: bool
    backups: list[BackupFile] = field(default_factory=list)
    last_error: str = ""

    @property
    def latest(self) -> BackupFile | None:
        """The newest backup, or ``None`` when none has been taken."""
        return self.backups[0] if self.backups else None

    @property
    def total_bytes(self) -> int:
        """Disk taken by every retained backup."""
        return sum(backup.size_bytes for backup in self.backups)

    @property
    def due_at(self) -> datetime | None:
        """When the next automatic backup falls due.

        ``None`` when the schedule is off. A schedule that is on but has no
        backup yet is due immediately, which is reported as "now".
        """
        if not self.automatic_enabled:
            return None
        latest = self.latest
        if latest is None:
            return utcnow()
        return latest.created_at + timedelta(hours=max(1, self.interval_hours))

    @property
    def is_due(self) -> bool:
        """True when an automatic backup should run."""
        due = self.due_at
        return due is not None and due <= utcnow()


class BackupService:
    """Creates, schedules, lists and exports database backups (§111)."""

    def __init__(
        self,
        db: DatabaseManager,
        settings: SettingsService,
        audit: AuditService,
        access: AccessControl,
        default_directory: Path,
        event_bus: EventBus | None = None,
    ) -> None:
        """Wire the service to its collaborators.

        Args:
            default_directory: used when ``backup.directory`` is left empty.
        """
        self._db = db
        self._settings = settings
        self._audit = audit
        self._access = access
        self._default_directory = Path(default_directory)
        self._bus = event_bus
        #: One backup at a time: a manual run and a scheduled run must never
        #: dump the same database concurrently.
        self._lock = threading.Lock()
        self._last_error = ""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    @property
    def directory(self) -> Path:
        """Where backups are written, from settings or the default."""
        configured = str(self._settings.get_str("backup.directory", "")).strip()
        return Path(configured) if configured else self._default_directory

    @property
    def tool_path(self) -> str:
        """Path to ``mysqldump``, or an empty string when it is not installed."""
        return shutil.which("mysqldump") or shutil.which("mysqldump.exe") or ""

    def status(self, session: Session | None = None) -> BackupStatus:
        """Describe the current arrangement and the backups that exist.

        Args:
            session: checked for ``data.maintain`` when given. The scheduled
                job calls this with no session, as the system itself.
        """
        if session is not None:
            self._access.require(session, Permission.DATA_MAINTAIN, target="backup")
        return BackupStatus(
            directory=self.directory,
            automatic_enabled=self._settings.get_bool("backup.automatic_enabled", False),
            interval_hours=max(1, self._settings.get_int("backup.interval_hours", 24)),
            keep_files=max(0, self._settings.get_int("backup.keep_files", 7)),
            tool_available=bool(self.tool_path),
            backups=self.list_backups(),
            last_error=self._last_error,
        )

    # ------------------------------------------------------------------
    # Reading what exists
    # ------------------------------------------------------------------
    def list_backups(self) -> list[BackupFile]:
        """Every backup in the configured directory, newest first.

        Only files this service would have written are listed, so an unrelated
        file sharing the folder is neither reported as a backup nor at risk of
        being pruned as one.
        """
        directory = self.directory
        if not directory.is_dir():
            return []
        found: list[BackupFile] = []
        for path in directory.iterdir():
            if not self._is_backup(path):
                continue
            try:
                stat = path.stat()
            except OSError:  # pragma: no cover - removed between listing and stat
                continue
            found.append(
                BackupFile(
                    path=path,
                    size_bytes=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                )
            )
        found.sort(key=lambda backup: backup.created_at, reverse=True)
        return found

    @staticmethod
    def _is_backup(path: Path) -> bool:
        """True for a file this service wrote."""
        return (
            path.is_file()
            and path.name.startswith(BACKUP_PREFIX)
            and path.suffix == BACKUP_SUFFIX
        )

    # ------------------------------------------------------------------
    # Making one
    # ------------------------------------------------------------------
    def create(self, session: Session, destination: Path | None = None) -> Path:
        """Back up the database now.

        Args:
            destination: an exact file to write, chosen by the operator. When
                omitted the backup is written to the configured directory
                under a timestamped name.

        Raises:
            PermissionDeniedError: without ``data.maintain``.
            ValidationFailedError: when ``mysqldump`` is missing or fails, or
                when the destination already exists.
        """
        live = self._access.require(session, Permission.DATA_MAINTAIN, target="backup")
        target = self._dump(destination)
        size = target.stat().st_size
        self._audit.record(
            AuditAction.DATABASE_BACKUP,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="backup",
            target_id=target.name,
            detail=f"Database backup written to {target} ({size:,} bytes).",
        )
        LOGGER.info("Database backup written to %s (%s bytes).", target, size)
        if destination is None:
            self.prune()
        return target

    def run_scheduled(self) -> Path | None:
        """Back up if the schedule says one is due, as the system itself.

        Returns the file written, or ``None`` when the schedule is off or the
        interval has not elapsed. This is the scheduler's callback, so it
        reports a failure rather than raising into the job runner.
        """
        status = self.status()
        if not status.automatic_enabled or not status.is_due:
            return None
        if not status.tool_available:
            self._report_failure(
                "mysqldump is not installed, so the scheduled backup could not run."
            )
            return None
        try:
            target = self._dump(None)
        except ValidationFailedError as exc:
            self._report_failure(exc.user_message or str(exc))
            return None

        size = target.stat().st_size
        self._last_error = ""
        self._audit.record(
            AuditAction.DATABASE_BACKUP,
            session=None,
            username="scheduler",
            category=AuditCategory.ADMINISTRATION,
            target_type="backup",
            target_id=target.name,
            detail=(
                f"Scheduled database backup written to {target} ({size:,} bytes) "
                f"after the configured {status.interval_hours}h interval."
            ),
        )
        removed = self.prune()
        LOGGER.info(
            "Scheduled backup written to %s (%s bytes); %d old file(s) removed.",
            target, size, removed,
        )
        self._notify(
            "Database backup completed",
            f"{target.name} - {size:,} bytes written to {target.parent}.",
            NotificationLevel.SUCCESS,
        )
        return target

    def _generated_name(self, database: str) -> Path:
        """A free, timestamped filename in the backup directory.

        The stamp is only accurate to the second, so a manual backup and a
        scheduled one landing in the same second would collide. Rather than
        overwrite one - or fail the scheduled run, which is how an operator
        ends up believing in a backup that never happened - the name takes a
        counter until it is free.
        """
        directory = self.directory
        stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"{BACKUP_PREFIX}{database}_{stamp}"
        candidate = directory / safe_filename(f"{base}{BACKUP_SUFFIX}")
        suffix = 2
        while candidate.exists():
            candidate = directory / safe_filename(f"{base}_{suffix}{BACKUP_SUFFIX}")
            suffix += 1
        return candidate

    def _dump(self, destination: Path | None) -> Path:
        """Run ``mysqldump`` into ``destination`` or a timestamped file."""
        tool = self.tool_path
        if not tool:
            raise ValidationFailedError(
                "mysqldump not found.",
                user_message=(
                    "Database backup needs the 'mysqldump' tool, which ships "
                    "with MySQL. Add the MySQL bin directory to PATH and try "
                    "again."
                ),
            )

        settings = self._db.settings
        if destination is None:
            target = self._generated_name(settings.database)
        else:
            # A destination the operator typed is theirs: refusing is right
            # here, because silently renaming their file would be worse than
            # telling them the name is taken.
            target = Path(destination)
            if target.exists():
                raise ValidationFailedError(
                    "Backup file already exists.",
                    user_message=(
                        f"A file named {target.name} already exists in "
                        f"{target.parent}. Choose another name."
                    ),
                )
        target.parent.mkdir(parents=True, exist_ok=True)

        # The password goes through the environment, never on the command
        # line, so it cannot be read out of the process list.
        environment = dict(os.environ)
        environment["MYSQL_PWD"] = settings.password
        command = [
            tool,
            f"--host={settings.host}",
            f"--port={settings.port}",
            f"--user={settings.user}",
            "--single-transaction",
            "--skip-lock-tables",
            "--routines",
            settings.database,
        ]

        with self._lock:
            try:
                with target.open("w", encoding="utf-8") as handle:
                    completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                        command,
                        stdout=handle,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=environment,
                        timeout=DUMP_TIMEOUT,
                        check=False,
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                target.unlink(missing_ok=True)
                raise ValidationFailedError(
                    f"Backup failed: {exc}",
                    user_message=f"The database backup could not be created: {exc}",
                ) from exc

        if completed.returncode != 0:
            error = (completed.stderr or "").strip()[:300]
            target.unlink(missing_ok=True)
            raise ValidationFailedError(
                f"mysqldump exited {completed.returncode}: {error}",
                user_message=f"The database backup failed: {error}",
            )
        return target

    # ------------------------------------------------------------------
    # Keeping the folder in order
    # ------------------------------------------------------------------
    def prune(self) -> int:
        """Delete the oldest backups beyond ``backup.keep_files``.

        Returns the number of files removed. A keep count of zero keeps every
        file. Only files this service wrote are ever considered, and the
        newest is never removed whatever the setting says.
        """
        keep = max(0, self._settings.get_int("backup.keep_files", 7))
        if keep <= 0:
            return 0
        backups = self.list_backups()
        removed = 0
        for backup in backups[max(1, keep):]:
            try:
                backup.path.unlink()
            except OSError as exc:  # pragma: no cover - permissions, races
                LOGGER.warning("Could not remove old backup %s: %s", backup.path, exc)
                continue
            removed += 1
            LOGGER.info("Removed old backup %s.", backup.name)
        return removed

    def delete(self, session: Session, name: str) -> None:
        """Delete one named backup from the configured directory.

        The name is resolved inside the backup directory and must be a file
        this service wrote, so no other path can be reached through it.

        Raises:
            PermissionDeniedError: without ``data.maintain``.
            ValidationFailedError: when the name is not a backup in the folder.
        """
        live = self._access.require(session, Permission.DATA_MAINTAIN, target="backup")
        target = self._resolve(name)
        target.unlink()
        self._audit.record(
            AuditAction.DATABASE_BACKUP,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="backup",
            target_id=target.name,
            result="WARNING",
            detail=f"Backup file {target.name} was deleted by an administrator.",
        )
        LOGGER.info("Backup %s deleted.", target.name)

    def save_copy(self, session: Session, name: str, destination: Path) -> Path:
        """Copy an existing backup to a location the operator chose.

        Raises:
            PermissionDeniedError: without ``data.maintain``.
            ValidationFailedError: when the backup is unknown or the copy fails.
        """
        live = self._access.require(session, Permission.DATA_MAINTAIN, target="backup")
        source = self._resolve(name)
        target = Path(destination)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        except OSError as exc:
            raise ValidationFailedError(
                f"Could not copy backup: {exc}",
                user_message=f"The backup could not be saved to {target}: {exc}",
            ) from exc
        self._audit.record(
            AuditAction.DATABASE_BACKUP,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="backup",
            target_id=source.name,
            detail=f"Backup {source.name} was copied to {target}.",
        )
        LOGGER.info("Backup %s copied to %s.", source.name, target)
        return target

    def _resolve(self, name: str) -> Path:
        """The backup called ``name``, guaranteed to be inside the folder."""
        candidate = self.directory / Path(str(name)).name
        if not self._is_backup(candidate):
            raise ValidationFailedError(
                f"Unknown backup {name!r}.",
                user_message=(
                    f"{name} is not a backup file in {self.directory}. "
                    "Refresh the list and try again."
                ),
            )
        return candidate

    # ------------------------------------------------------------------
    # Telling the operator
    # ------------------------------------------------------------------
    def _report_failure(self, message: str) -> None:
        """Record and surface a scheduled backup that did not happen."""
        self._last_error = message
        LOGGER.error("Scheduled backup failed: %s", message)
        self._audit.record(
            AuditAction.DATABASE_BACKUP,
            session=None,
            username="scheduler",
            category=AuditCategory.ADMINISTRATION,
            target_type="backup",
            result="FAILURE",
            detail=f"Scheduled database backup failed: {message}",
        )
        self._notify("Database backup failed", message, NotificationLevel.ERROR)

    def _notify(self, title: str, message: str, level: str) -> None:
        """Raise an in-application notification, if a bus is wired."""
        if self._bus is None:
            return
        self._bus.publish(
            EventType.NOTIFICATION_RAISED,
            NotificationPayload(
                title=title,
                message=message,
                level=level,
                category="maintenance",
                reference_type="backup",
            ),
        )
