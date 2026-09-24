"""Where AETHRA-SEC keeps its files, in every way it can be started.

There are three shapes the application runs in, and a path that is right for
one is wrong for the others:

* **a developer checkout** - ``python -m aethra_sec.main`` from the repository.
  Everything lives beside the source, which is what makes ``run.bat``,
  ``setup.bat`` and the test suite work without configuration.
* **an installed build** - ``AETHRA-SEC.exe`` under ``C:\\Program Files``. The
  install directory is read-only for the operator, so nothing writable may be
  placed there. Configuration, logs, captures and reports go to a per-machine
  application-data directory that survives upgrade and uninstall.
* **a frozen one-file bundle** - the same executable unpacked into a temporary
  directory that is deleted on exit. Read-only assets are read from there;
  writing to it would silently lose the data.

The distinction this module exists to keep is between *code and assets*, which
ship with the build and are read-only, and *state*, which the operator creates
and must outlive the build. :func:`bundle_root` answers the first,
:func:`data_dir` the second, and neither is ever derived from the process's
current working directory - a desktop shortcut sets that to somewhere
unrelated, which is exactly the failure this module prevents.

Every location can be overridden by an environment variable, which is what lets
the installer, the test suite and a portable copy each place state where they
need it without a code change.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

#: Folder name used under %PROGRAMDATA% and for the install directory.
APP_DIRNAME = "AETHRA-SEC"

#: Configuration file name. Not ``.env``: an installed application's
#: configuration is not a dotfile, and Explorer hides those by default, which
#: makes a support request harder than it needs to be.
CONFIG_FILENAME = "aethra-sec.env"

#: Environment overrides, highest priority.
DATA_DIR_VAR = "AETHRA_DATA_DIR"
CONFIG_FILE_VAR = "AETHRA_CONFIG_FILE"


def is_frozen() -> bool:
    """True when running from a PyInstaller build rather than from source."""
    return bool(getattr(sys, "frozen", False))


def _onefile_temp_dir() -> Path | None:
    """The temporary unpack directory of a one-file build, when there is one."""
    meipass = getattr(sys, "_MEIPASS", None)
    return Path(meipass) if meipass else None


def bundle_root() -> Path:
    """Directory holding the read-only files that ship with the application.

    For a frozen build this is the unpack directory (one-file) or the
    executable's own folder (one-directory). For a checkout it is the
    repository root. Assets are read from here and nothing is ever written.
    """
    if is_frozen():
        unpacked = _onefile_temp_dir()
        if unpacked is not None:
            return unpacked
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def install_root() -> Path:
    """Directory the application was installed or checked out into.

    Unlike :func:`bundle_root` this is stable across a one-file run - it is the
    folder the operator sees, the one the shortcut points at and the one the
    uninstaller removes.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def _program_data() -> Path:
    """The machine-wide application-data directory.

    ``%PROGRAMDATA%`` on Windows; the XDG location elsewhere, so the Linux lab
    servers the project also runs on get a sensible home rather than a path
    with a Windows shape.
    """
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE")
        if base:
            return Path(base)
        return Path(os.environ.get("SystemDrive", "C:")) / "ProgramData"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg)
    return Path.home() / ".local" / "share"


def data_dir() -> Path:
    """Writable directory holding configuration, logs, captures and reports.

    A checkout keeps its state beside the source, because that is what a
    developer expects and what the existing scripts already assume. An
    installed build cannot: ``C:\\Program Files`` is not writable by the
    operator, and state placed there would also be destroyed by the next
    upgrade. So the two cases genuinely differ, and this is where they part.
    """
    override = os.environ.get(DATA_DIR_VAR, "").strip()
    if override:
        return Path(override).expanduser()
    if is_frozen():
        return _program_data() / APP_DIRNAME
    return install_root()


def config_file() -> Path:
    """The configuration file this installation reads and writes.

    A checkout keeps using ``.env`` so an existing developer setup is not
    invalidated by this change; an installed build uses a plainly-named file in
    the application-data directory.
    """
    override = os.environ.get(CONFIG_FILE_VAR, "").strip()
    if override:
        return Path(override).expanduser()
    if is_frozen():
        return data_dir() / CONFIG_FILENAME
    return install_root() / ".env"


def config_file_name() -> str:
    """Just the configuration file's name, for a message that has no room.

    A checkout says ``.env`` and an installed build says ``aethra-sec.env``.
    Messages that can afford the whole path should use :func:`config_file`;
    this exists so the short ones are still correct rather than telling an
    installed user to edit a file that is not there.
    """
    return config_file().name


def log_dir() -> Path:
    """Default directory for application and setup logs."""
    return data_dir() / "logs"


def report_dir() -> Path:
    """Default directory for generated reports."""
    return data_dir() / "reports_output"


def capture_dir() -> Path:
    """Default directory for capture files."""
    return data_dir() / "captures"


def ensure_data_dirs() -> tuple[Path, ...]:
    """Create the writable directories, returning the ones that now exist.

    Never raises. A directory that cannot be created is left out of the result
    and reported by the caller - a read-only reports folder is a problem to
    show on the health screen, not a reason to refuse to start.
    """
    created: list[Path] = []
    for directory in (data_dir(), log_dir(), report_dir(), capture_dir()):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            created.append(directory)
        except OSError:
            continue
    return tuple(created)


def describe() -> dict[str, str]:
    """Every resolved location, for diagnostics and the health screen."""
    return {
        "mode": "installed build" if is_frozen() else "source checkout",
        "install_root": str(install_root()),
        "bundle_root": str(bundle_root()),
        "data_dir": str(data_dir()),
        "config_file": str(config_file()),
        "log_dir": str(log_dir()),
        "report_dir": str(report_dir()),
        "capture_dir": str(capture_dir()),
    }
