"""Environment-variable access helpers.

Configuration precedence, highest first:

1. real process environment variables;
2. ``.env`` in the project root (loaded via ``python-dotenv`` when available,
   otherwise by a small built-in parser so the application still starts);
3. the defaults declared in :mod:`aethra_sec.config.defaults` /
   :mod:`aethra_sec.config.settings`.

Credentials are never written to disk by this module and never logged.
"""

from __future__ import annotations

import os
from pathlib import Path

from aethra_sec.config import paths

_ENV_PREFIX = "AETHRA_"
_loaded_env_file: Path | None = None


def project_root() -> Path:
    """Absolute path of the repository/installation root.

    Delegates to :func:`aethra_sec.config.paths.install_root`, which knows the
    difference between a source checkout and an installed build. Kept as a name
    because the scripts and the older modules call it.
    """
    return paths.install_root()


def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal ``KEY=VALUE`` parser used when python-dotenv is absent."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_env_file(path: Path | None = None) -> Path | None:
    """Load ``.env`` into ``os.environ`` without overriding real env vars.

    Args:
        path: explicit configuration file; defaults to the one this
            installation owns (see :func:`aethra_sec.config.paths.config_file`)
            - ``.env`` beside the source in a checkout, a named file in the
            application-data directory for an installed build.

    Returns:
        The path that was loaded, or ``None`` when no file was found.
    """
    global _loaded_env_file

    env_path = path or paths.config_file()
    if not env_path.is_file():
        return None

    try:  # pragma: no cover - trivial import branch
        from dotenv import load_dotenv

        load_dotenv(env_path, override=False)
    except Exception:
        for key, value in _parse_env_file(env_path).items():
            os.environ.setdefault(key, value)

    _loaded_env_file = env_path
    return env_path


def loaded_env_file() -> Path | None:
    """Path of the ``.env`` file that was loaded, if any (for diagnostics)."""
    return _loaded_env_file


def env_str(name: str, default: str = "") -> str:
    """Read a string environment variable, trimming surrounding whitespace."""
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def env_int(name: str, default: int) -> int:
    """Read an integer environment variable, falling back on malformed input."""
    raw = env_str(name)
    if not raw:
        return default
    try:
        return int(raw, 10)
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable (``true/yes/on/1`` are true)."""
    raw = env_str(name).lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on", "enabled"}:
        return True
    if raw in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


def env_list(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Read a comma-separated environment variable into a tuple."""
    raw = env_str(name)
    if not raw:
        return tuple(default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def env_path(name: str) -> Path | None:
    """Read a filesystem path environment variable (``None`` when unset)."""
    raw = env_str(name)
    return Path(raw).expanduser() if raw else None


def describe_environment() -> dict[str, str]:
    """Return non-secret ``AETHRA_*`` variables for the diagnostics screen.

    Secret-bearing keys are redacted rather than omitted so the operator can see
    whether a value is configured without the value being displayed or logged.
    """
    secret_markers = ("PASSWORD", "SECRET", "TOKEN", "KEY")
    described: dict[str, str] = {}
    for key, value in sorted(os.environ.items()):
        if not key.startswith(_ENV_PREFIX):
            continue
        if any(marker in key.upper() for marker in secret_markers):
            described[key] = "(set)" if value.strip() else "(not set)"
        else:
            described[key] = value
    return described
