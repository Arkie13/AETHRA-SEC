"""Files that ship with AETHRA-SEC, located however it was started (§119).

The application is launched three ways - ``run.bat`` from the project folder, a
desktop shortcut whose working directory is somewhere else entirely, and
``python -m aethra_sec.main`` from a terminal. A path written relative to the
current directory works in the first case and silently fails in the others,
which is the failure this module exists to prevent.

Every path here is resolved from :func:`aethra_sec.config.paths.bundle_root`,
which is derived from where the build actually put its files - the package's
own location in a checkout, the unpack directory of a frozen one-file build -
rather than from the process's working directory. It is therefore correct
wherever the process was started from, and :func:`resolve` is deliberately the
only way a caller obtains one.

Nothing here raises for a missing file. A packaged asset that has been deleted
is a real possibility - a partial copy, an antivirus quarantine - and the
answer is that the caller is told and degrades, not that the console fails to
start over a sound effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aethra_sec.config.paths import bundle_root
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("resources")

#: Directory holding everything that ships with the application.
ASSETS_DIRNAME = "assets"

#: The security alert sound. Supplied by the operator and packaged verbatim -
#: it is never re-encoded, trimmed or substituted, so what plays is the file
#: that was provided.
SECURITY_ALERT_SOUND = "security-alert.mp3"

#: The application icon, used by the desktop shortcut.
APPLICATION_ICON = "aethra-sec.ico"


@dataclass(frozen=True)
class Asset:
    """A packaged file and whether it is actually there.

    Attributes:
        name: file name inside the assets directory.
        path: absolute path it should occupy.
        available: whether it exists and is readable *now*.
        detail: why it is unavailable, phrased for an operator. Empty when it
            is available.
    """

    name: str
    path: Path
    available: bool
    detail: str = ""

    @property
    def size_bytes(self) -> int:
        """Size on disk, or 0 when it is missing."""
        try:
            return self.path.stat().st_size
        except OSError:
            return 0


def assets_dir() -> Path:
    """The assets directory, resolved from where the build put its files."""
    return bundle_root() / ASSETS_DIRNAME


def resolve(name: str) -> Asset:
    """Locate one packaged file and report whether it is usable.

    Checks readability rather than mere existence: a file that is present but
    locked - mid-copy, or held by another process - is not usable, and saying
    so here is better than a failure at the moment an alert fires.
    """
    path = assets_dir() / name
    try:
        if not path.is_file():
            return Asset(
                name, path, False,
                f"{name} is not present in {assets_dir()}.",
            )
        with path.open("rb") as handle:
            handle.read(1)
    except OSError as exc:
        return Asset(name, path, False, f"{name} could not be read: {exc}")
    return Asset(name, path, True)


def security_alert_sound() -> Asset:
    """The packaged security alert sound."""
    return resolve(SECURITY_ALERT_SOUND)
