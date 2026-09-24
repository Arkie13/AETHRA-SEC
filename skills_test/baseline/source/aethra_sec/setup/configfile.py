"""Reading and writing this installation's configuration file.

Every configured value AETHRA-SEC needs lives in one file of ``KEY=value``
lines - the same format the developer checkout has always used as ``.env``, so
one parser serves both shapes of installation.

Three properties are worth stating, because each is a decision rather than an
accident:

* **Existing content is preserved.** Writing a key rewrites that key's line in
  place and leaves every other line, comment and blank line exactly as it was.
  An upgrade that reset an operator's tuning would be a data loss, and setup is
  explicitly allowed to be run again.
* **Secrets go in this file and nowhere else.** They are never written to a
  log, an audit record or the console, and this module never prints a value
  back. The file itself is the boundary, and :func:`harden_permissions` makes
  it one on Windows.
* **A write is atomic.** The new content is written beside the target and moved
  over it, so an interrupted save cannot leave a half-written configuration
  that stops the application from starting.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aethra_sec.config import paths
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("setup.configfile")

#: Keys whose values must never be echoed, logged or included in diagnostics.
SECRET_KEYS = frozenset({"AETHRA_DB_PASSWORD", "AETHRA_SMTP_PASSWORD"})

#: The header written into a configuration file this module creates.
HEADER = """\
# ---------------------------------------------------------------------------
# AETHRA-SEC configuration
#
# Written by the AETHRA-SEC setup wizard. Safe to edit by hand; the wizard
# rewrites individual keys and leaves everything else, including comments,
# exactly as it found them.
#
# This file contains credentials. It is not part of the application install
# and is not removed by an upgrade.
#
# Windows paths are written bare, with no quotes: inside double quotes a
# backslash starts an escape sequence, so "C:\\Snort\\alert.ids" turns the \\a
# into a bell character and the path silently stops existing.
# ---------------------------------------------------------------------------
"""


@dataclass(frozen=True)
class ConfigFile:
    """One configuration file and the values it currently holds.

    ``readable`` matters more than it looks. A file that exists but cannot be
    opened - the wrong access-control entry, a lock, a roaming profile that has
    not synchronised - must not be mistaken for a file that is not there. The
    two look identical to a caller that only checks whether any values came
    back, and treating the first as the second would run first-run setup over a
    working deployment.
    """

    path: Path
    values: dict[str, str]
    readable: bool = True
    error: str = ""

    @property
    def exists(self) -> bool:
        """True when the file is present on disk."""
        return self.path.is_file()

    def get(self, key: str, default: str = "") -> str:
        """Read one value."""
        return self.values.get(key, default)

    def describe(self) -> dict[str, str]:
        """Every value, with secrets replaced by whether they are set."""
        return {
            key: ("(set)" if value.strip() else "(not set)")
            if key in SECRET_KEYS
            else value
            for key, value in sorted(self.values.items())
        }


def parse(text: str) -> dict[str, str]:
    """Parse ``KEY=value`` lines, ignoring comments and blanks."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load(path: Path | None = None) -> ConfigFile:
    """Read the configuration file, or an empty one when it does not exist.

    A file that is present but unreadable is reported as such rather than as an
    absent one, because the two demand opposite responses: an absent file means
    run setup, and an unreadable file means fix the permissions and do not
    touch the deployment that is already there.
    """
    target = Path(path) if path is not None else paths.config_file()
    if not target.is_file():
        return ConfigFile(target, {}, readable=False, error="")
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        LOGGER.error(
            "The configuration file %s exists but could not be read: %s",
            target, exc,
        )
        return ConfigFile(target, {}, readable=False, error=str(exc))
    return ConfigFile(target, parse(text), readable=True)


def write(values: dict[str, str], path: Path | None = None) -> Path:
    """Set keys in the configuration file, preserving everything else.

    Args:
        values: keys to set. A key already present is rewritten in place; a new
            one is appended. Keys not mentioned are left alone.
        path: file to write; defaults to this installation's own.

    Returns:
        The path that was written.

    Raises:
        OSError: when the file cannot be written. The caller reports it - a
            configuration that could not be saved must not look like one that
            was.
    """
    target = Path(path) if path is not None else paths.config_file()
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        existing = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        existing = HEADER.splitlines()

    remaining = dict(values)
    output: list[str] = []
    for line in existing:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}")
                continue
        output.append(line)

    if remaining:
        if output and output[-1].strip():
            output.append("")
        for key, value in remaining.items():
            output.append(f"{key}={value}")

    # Atomic replace: an interrupted save must not be able to leave a
    # half-written configuration behind.
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text("\n".join(output).rstrip("\n") + "\n", encoding="utf-8")
    os.replace(temporary, target)

    harden_permissions(target)
    LOGGER.info(
        "Configuration written to %s (%d key(s) updated).", target, len(values)
    )
    return target


def _is_readable(path: Path) -> bool:
    """Whether this process can actually open the file for reading."""
    try:
        with path.open("rb") as handle:
            handle.read(1)
        return True
    except OSError:
        return False


def harden_permissions(path: Path) -> bool:
    """Restrict the configuration file to administrators, SYSTEM and its owner.

    The file holds a database password and, when configured, an SMTP password.
    In ``%PROGRAMDATA%`` the inherited access-control list would let any local
    user read it, which is not an acceptable home for a credential.

    The owner is granted access alongside Administrators and SYSTEM, and that
    inclusion is the whole subtlety here. Granting only the first two produces
    a file the application cannot read unless it happens to be running
    elevated - and the failure is silent, because an unreadable configuration
    looks exactly like an absent one. Setup would then appear to succeed and
    the next start would behave as though the machine had never been
    configured. So the account that wrote the file keeps access to it, and the
    result is verified rather than assumed: if the file has become unreadable
    to this process, the restriction is rolled back and the caller is told.

    Returns True when the file ended up restricted *and* still readable. A
    failure is logged and reported rather than raised: an installation that
    could not tighten the ACL still needs to run, and the health report says so.
    """
    if os.name != "nt":
        try:
            path.chmod(0o600)
            return True
        except OSError as exc:
            LOGGER.warning("Could not restrict %s: %s", path, exc)
            return False

    icacls = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe"
    )
    if not os.path.isfile(icacls):
        return False

    grants = [
        "/grant:r", "*S-1-5-32-544:(F)",   # BUILTIN\Administrators
        "/grant:r", "*S-1-5-18:(F)",       # NT AUTHORITY\SYSTEM
    ]
    owner = _current_account()
    if owner:
        grants += ["/grant:r", f"{owner}:(F)"]

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [icacls, str(path), "/inheritance:r", *grants],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.warning("Could not restrict %s: %s", path, exc)
        return False
    if completed.returncode != 0:
        LOGGER.warning(
            "icacls could not restrict %s: %s",
            path, (completed.stderr or completed.stdout or "").strip()[:200],
        )
        return False

    if not _is_readable(path):
        # The restriction locked this process out of the file it just wrote.
        # A configuration that cannot be read is worse than one an
        # administrator could read, so inheritance goes back on.
        LOGGER.error(
            "Restricting %s made it unreadable to this process; the "
            "restriction has been reverted so the application can start.",
            path,
        )
        _restore_inheritance(path, icacls)
        return False

    LOGGER.info(
        "Configuration file permissions restricted to Administrators, SYSTEM%s.",
        f" and {owner}" if owner else "",
    )
    return True


def _current_account() -> str:
    """``DOMAIN\\user`` for the account this process runs as, or empty."""
    user = os.environ.get("USERNAME", "").strip()
    if not user:
        return ""
    domain = os.environ.get("USERDOMAIN", "").strip()
    return f"{domain}\\{user}" if domain else user


def _restore_inheritance(path: Path, icacls: str) -> None:
    """Put the inherited access-control list back after a failed restriction."""
    try:
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [icacls, str(path), "/reset"],
            capture_output=True, text=True, timeout=30, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.error("Could not restore permissions on %s: %s", path, exc)


def permissions_are_restricted(path: Path) -> tuple[bool, str]:
    """Report whether the configuration file is readable by ordinary users."""
    if not path.is_file():
        return False, "The configuration file does not exist."
    if os.name != "nt":
        mode = path.stat().st_mode & 0o777
        return (mode & 0o077) == 0, f"mode {mode:04o}"

    icacls = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe"
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [icacls, str(path)],
            capture_output=True, text=True, timeout=20, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"permissions could not be read: {exc}"
    text = completed.stdout or ""
    broad = [
        marker for marker in ("Users:", "Everyone:", "BUILTIN\\Users")
        if marker in text
    ]
    if broad:
        return False, f"readable by {', '.join(broad)}"
    # Report who actually holds access rather than a fixed sentence: the owner
    # is granted alongside Administrators and SYSTEM, and a status line that
    # named only the first two would be describing a different file.
    grantees: list[str] = []
    for line in text.splitlines():
        _, separator, entry = line.partition(str(path))
        candidate = (entry if separator else line).strip()
        name, colon, _rights = candidate.partition(":")
        if colon and name and not name.endswith(".env"):
            grantees.append(name.strip())
    if grantees:
        return True, "restricted to " + ", ".join(dict.fromkeys(grantees))
    return True, "restricted to Administrators and SYSTEM"


def build_values(
    *,
    db_host: str,
    db_port: int,
    db_name: str,
    db_user: str,
    db_password: str,
    nmap_path: str = "",
    tshark_path: str = "",
    snort_path: str = "",
    snort_config: str = "",
    snort_transport: str = "disabled",
    snort_alert_file: str = "",
    capture_interface: str = "",
    authorized_networks: str = "",
    smtp_host: str = "",
    smtp_port: int = 587,
    smtp_user: str = "",
    smtp_password: str = "",
    smtp_from: str = "",
    smtp_to: str = "",
    smtp_starttls: bool = True,
) -> dict[str, str]:
    """Assemble the configuration keys the wizard collected.

    Every value is written even when empty: an empty ``AETHRA_NMAP_PATH`` is
    meaningful - it says "discover it on PATH" - and writing it keeps the file
    a complete description of the deployment rather than a partial one whose
    gaps have to be inferred from defaults.
    """
    return {
        "AETHRA_DB_HOST": db_host,
        "AETHRA_DB_PORT": str(db_port),
        "AETHRA_DB_NAME": db_name,
        "AETHRA_DB_USER": db_user,
        "AETHRA_DB_PASSWORD": db_password,
        "AETHRA_NMAP_PATH": nmap_path,
        "AETHRA_TSHARK_PATH": tshark_path,
        "AETHRA_SNORT_PATH": snort_path,
        "AETHRA_SNORT_CONFIG": snort_config,
        "AETHRA_SNORT_TRANSPORT": snort_transport,
        "AETHRA_SNORT_ALERT_FILE": snort_alert_file,
        "AETHRA_CAPTURE_INTERFACE": capture_interface,
        "AETHRA_AUTHORIZED_NETWORKS": authorized_networks,
        "AETHRA_SMTP_HOST": smtp_host,
        "AETHRA_SMTP_PORT": str(smtp_port),
        "AETHRA_SMTP_USER": smtp_user,
        "AETHRA_SMTP_PASSWORD": smtp_password,
        "AETHRA_SMTP_FROM": smtp_from,
        "AETHRA_SMTP_TO": smtp_to,
        "AETHRA_SMTP_STARTTLS": "true" if smtp_starttls else "false",
    }


def is_configured(path: Path | None = None) -> bool:
    """True when this installation has already been set up.

    This is what the application asks on start to decide whether the first-run
    wizard is needed, so the bias runs one way throughout: anything short of
    clear evidence that the machine has never been configured counts as
    configured.

    * A file naming a database - configured, obviously.
    * A file that exists but cannot be read - configured. The permissions are
      wrong and the health screen will say so, but re-running setup over a
      deployment whose configuration merely could not be opened would be a far
      worse answer than starting and reporting the problem.
    * No file at all - not configured. This is the only case that runs setup.
    """
    config = load(path)
    if not config.exists:
        return False
    if not config.readable:
        LOGGER.warning(
            "%s exists but is unreadable; treating this installation as "
            "already configured rather than running setup over it.",
            config.path,
        )
        return True
    return bool(config.get("AETHRA_DB_NAME"))
