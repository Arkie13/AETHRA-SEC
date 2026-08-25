"""Structured application logging.

This is the *diagnostic* log (what the software did). It is distinct from the
*audit* log (what the operator did), which lives in MySQL with chained
integrity hashes - see :mod:`aethra_sec.security.audit`.

Credentials never reach this log: :class:`SecretRedactingFilter` scrubs common
secret-bearing patterns from every record before it is emitted.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 5

_configured = False

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(password\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(passwd\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(secret\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(token\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
)


class SecretRedactingFilter(logging.Filter):
    """Replace credential-looking values in log messages with ``***``."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D102
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = message
        for pattern in _REDACTION_PATTERNS:
            redacted = pattern.sub(r"\1***", redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(
    log_dir: Path,
    level: str = "INFO",
    *,
    console: bool = True,
    filename: str = "aethra_sec.log",
) -> Path | None:
    """Configure the root logger once, with rotation and redaction.

    Args:
        log_dir: directory for rotating log files; created when missing.
        level: one of DEBUG/INFO/WARNING/ERROR/CRITICAL.
        console: also emit to stderr (useful when launched from a terminal).
        filename: log file name inside ``log_dir``.

    Returns:
        The active log file path, or ``None`` when file logging could not be
        set up (in which case console logging still works and a warning is
        emitted - the application never fails to start because of logging).
    """
    global _configured

    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    if _configured:
        for handler in root.handlers:
            handler.setLevel(numeric_level)
        return _current_log_path(root)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    redactor = SecretRedactingFilter()

    log_path: Path | None = None
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / filename
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        file_handler.addFilter(redactor)
        root.addHandler(file_handler)
    except OSError as exc:
        log_path = None
        fallback = logging.StreamHandler(sys.stderr)
        fallback.setFormatter(formatter)
        fallback.addFilter(redactor)
        root.addHandler(fallback)
        root.warning("File logging unavailable (%s); logging to stderr only.", exc)

    if console:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(numeric_level)
        stream_handler.addFilter(redactor)
        root.addHandler(stream_handler)

    # Third-party libraries are noisy at DEBUG; keep them at WARNING.
    for noisy in ("pyshark", "mysql.connector", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # asyncio emits a WARNING when a child process is reaped by us rather than
    # by its own watcher, which happens every time capture is stopped. The real
    # capture state is reported by the capture counters and the status
    # indicator, so this specific noise is suppressed rather than alarming the
    # operator on every Stop.
    logging.getLogger("asyncio").setLevel(logging.ERROR)

    _configured = True
    return log_path


def _current_log_path(root: logging.Logger) -> Path | None:
    """Return the file path of the active rotating handler, if any."""
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            return Path(handler.baseFilename)
    return None


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger (``aethra_sec.<name>``)."""
    if name.startswith("aethra_sec"):
        return logging.getLogger(name)
    return logging.getLogger(f"aethra_sec.{name}")
