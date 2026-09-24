"""Dependency verification that actually exercises each tool.

The distinction this module is built around is between *finding* a tool and
*proving it works*. Those are not the same answer, and reporting the first as
though it were the second is how an operator ends up with a console that says
Nmap is fine and a scan that fails on the first attempt.

So nothing here passes on the existence of a file:

* **Nmap** is run against ``127.0.0.1`` with XML output, and the XML is parsed.
  A binary that is present but cannot execute, cannot open a socket, or emits
  XML the parser rejects is a failure, and the failure names which of those it
  was. The probe is a loopback host-discovery scan: it touches this machine
  only, so it is safe to run during setup on any network.
* **TShark** is asked for its version, then to enumerate interfaces, then to
  actually capture on one - a real one-second capture that must start, produce
  a readable file and stop. A TShark that exists but has no packet driver
  behind it fails at the third step, which is exactly where a real capture
  would fail later.
* **Snort** is version-checked and, when a configuration is supplied, run in
  its own test mode (``-T``), which validates the configuration and the rule
  files and exits without ever placing an interface in capture mode or writing
  an alert.

Every probe returns a :class:`ProbeResult` whose ``passed`` field is the truth
about that attempt. There is no "assumed working" state, and no probe invents a
version, a path or a result it did not observe.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("setup.detection")

#: Longest any single external command is allowed to take during setup. Long
#: enough for a cold-started Nmap on a busy machine, short enough that a hung
#: tool does not hold the wizard open indefinitely.
COMMAND_TIMEOUT = 60

#: Seconds of live traffic the TShark capture probe records. One second is
#: enough to prove the pipeline works and short enough not to make the wizard
#: feel stuck; the probe passes on a *successful capture*, never on the number
#: of packets, because a quiet lab segment is not a fault.
CAPTURE_PROBE_SECONDS = 1


@dataclass
class ProbeResult:
    """The outcome of one dependency check.

    Attributes:
        name: what was checked, as the operator sees it.
        passed: whether the tool was proven usable. Never optimistic.
        detail: what happened, in one line.
        version: the version string the tool reported, when it reported one.
        path: where the executable was found, when it was found.
        remedy: what to do about a failure. Empty when there is nothing to fix.
        evidence: the individual steps that were run, each with its own
            outcome, so a failure says which step failed rather than only that
            something did.
    """

    name: str
    passed: bool
    detail: str
    version: str = ""
    path: str = ""
    remedy: str = ""
    evidence: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """``PASS`` / ``FAIL`` for the health report."""
        return "PASS" if self.passed else "FAIL"

    def add(self, step: str, ok: bool, note: str = "") -> None:
        """Record one verification step and what it produced."""
        mark = "ok" if ok else "failed"
        self.evidence.append(f"{step}: {mark}{f' - {note}' if note else ''}")


def _run(argv: list[str], timeout: int = COMMAND_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run a command with a fixed argument list and no shell."""
    return subprocess.run(  # noqa: S603 - fixed argv, shell=False
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        creationflags=_no_window(),
    )


def _no_window() -> int:
    """Keep console windows from flashing over the wizard on Windows."""
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _first_line(completed: subprocess.CompletedProcess[str]) -> str:
    """The first line of a tool's output, wherever it wrote it."""
    text = (completed.stdout or "") + (completed.stderr or "")
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def probe_nmap(configured_path: Path | None = None) -> ProbeResult:
    """Verify Nmap end to end: execute it, get XML, and parse the XML.

    The validation scan is ``-sn -oX - 127.0.0.1`` - host discovery only,
    against the loopback address. It sends nothing onto the network, so it is
    safe to run unattended during installation, and it still exercises every
    part of the path a real assessment uses: process launch, argument handling,
    permission to open the socket, XML emission and XML parsing.
    """
    from aethra_sec.integrations.nmap.runner import PYTHON_NMAP_AVAILABLE, find_nmap

    result = ProbeResult("Nmap", False, "")

    if not PYTHON_NMAP_AVAILABLE:
        result.add("python-nmap library", False)
        result.detail = "The python-nmap library is not importable."
        result.remedy = "Reinstall AETHRA-SEC, or run: pip install python-nmap"
        return result
    result.add("python-nmap library", True)

    executable = find_nmap(configured_path)
    if executable is None:
        result.add("locate nmap", False)
        result.detail = "NMAP UNAVAILABLE - the executable was not found."
        result.remedy = (
            "Install Nmap from https://nmap.org/download.html and let the "
            "installer add it to PATH, then re-run this check."
        )
        return result
    result.path = str(executable)
    result.add("locate nmap", True, str(executable))

    try:
        version_run = _run([str(executable), "--version"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("nmap --version", False, str(exc))
        result.detail = f"Nmap was found at {executable} but could not run: {exc}"
        result.remedy = "Check that the file is executable and not blocked by policy."
        return result
    if version_run.returncode != 0:
        result.add("nmap --version", False, f"exit {version_run.returncode}")
        result.detail = (
            f"Nmap exited with code {version_run.returncode} when asked for its version."
        )
        result.remedy = "Reinstall Nmap; the installation looks incomplete."
        return result
    result.version = _first_line(version_run)
    result.add("nmap --version", True, result.version)

    # The real validation: a loopback host-discovery scan, in XML, parsed.
    try:
        scan = _run([str(executable), "-sn", "-oX", "-", "127.0.0.1"])
    except subprocess.TimeoutExpired:
        result.add("loopback scan", False, "timed out")
        result.detail = "Nmap did not finish a loopback scan within the timeout."
        result.remedy = (
            "Something is blocking Nmap from running - check anti-virus or "
            "endpoint protection, which commonly quarantines it."
        )
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("loopback scan", False, str(exc))
        result.detail = f"Nmap could not execute a scan: {exc}"
        return result

    if scan.returncode != 0:
        detail = _first_line(scan) or f"exit code {scan.returncode}"
        result.add("loopback scan", False, detail)
        result.detail = f"Nmap refused a loopback scan: {detail}"
        result.remedy = (
            "On Windows this is usually a missing Npcap installation or a "
            "permission problem; try running the scan from an elevated prompt."
        )
        return result
    result.add("loopback scan", True)

    try:
        root = ElementTree.fromstring(scan.stdout)
    except ElementTree.ParseError as exc:
        result.add("parse XML output", False, str(exc))
        result.detail = f"Nmap ran but its XML output could not be parsed: {exc}"
        result.remedy = (
            "The installed Nmap emits output this version does not understand. "
            "Install a current release from https://nmap.org/download.html."
        )
        return result
    if root.tag != "nmaprun":
        result.add("parse XML output", False, f"root element <{root.tag}>")
        result.detail = "Nmap produced XML that is not an Nmap scan document."
        return result
    result.add("parse XML output", True, f"<{root.tag}>")

    result.passed = True
    result.detail = f"{result.version} at {executable}; loopback scan parsed."
    return result


# ---------------------------------------------------------------------------
# TShark / PyShark
# ---------------------------------------------------------------------------
def probe_tshark(configured_path: Path | None = None) -> ProbeResult:
    """Verify TShark by running a real capture, not by finding the file.

    Four steps, and the last one is the one that matters: capture is started on
    a real interface for :data:`CAPTURE_PROBE_SECONDS`, must produce a readable
    file, and must stop on its own. A TShark installed without its packet
    driver passes the first three steps and fails this one, which is precisely
    the failure an operator would otherwise discover on the Traffic screen.
    """
    from aethra_sec.integrations.pyshark_capture.interfaces import find_tshark

    result = ProbeResult("TShark", False, "")

    executable = find_tshark(configured_path)
    if executable is None:
        result.add("locate tshark", False)
        result.detail = "TSHARK UNAVAILABLE - the executable was not found."
        result.remedy = (
            "Install Wireshark from https://www.wireshark.org/download.html "
            "with the TShark component and the Npcap driver."
        )
        return result
    result.path = str(executable)
    result.add("locate tshark", True, str(executable))

    try:
        version_run = _run([str(executable), "-v"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("tshark -v", False, str(exc))
        result.detail = f"TShark was found at {executable} but could not run: {exc}"
        return result
    result.version = _first_line(version_run)
    if version_run.returncode != 0 and not result.version:
        result.add("tshark -v", False, f"exit {version_run.returncode}")
        result.detail = "TShark did not report a version."
        result.remedy = "Reinstall Wireshark; the installation looks incomplete."
        return result
    result.add("tshark -v", True, result.version)

    # Interface enumeration. On Windows an empty list means the Npcap driver is
    # absent or the process is not elevated - both of which stop capture dead.
    try:
        listing = _run([str(executable), "-D"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("tshark -D", False, str(exc))
        result.detail = f"TShark could not enumerate interfaces: {exc}"
        return result
    devices = [line.strip() for line in (listing.stdout or "").splitlines() if line.strip()]
    if listing.returncode != 0 or not devices:
        note = _first_line(listing) or "no interfaces returned"
        result.add("tshark -D", False, note)
        result.detail = f"TShark listed no capture interfaces: {note}"
        result.remedy = (
            "Install the Npcap driver (bundled with Wireshark) and run "
            "AETHRA-SEC as Administrator. Without both, capture cannot start."
        )
        return result
    result.add("tshark -D", True, f"{len(devices)} interface(s)")

    capture_ok, capture_note, capture_remedy = _probe_capture(executable, devices)
    result.add("live capture", capture_ok, capture_note)
    if not capture_ok:
        result.detail = f"TShark cannot capture: {capture_note}"
        result.remedy = capture_remedy
        return result

    result.passed = True
    result.detail = (
        f"{result.version} at {executable}; {len(devices)} interface(s); "
        f"capture started and stopped cleanly."
    )
    return result


def _probe_capture(
    executable: Path, devices: list[str]
) -> tuple[bool, str, str]:
    """Start a real one-second capture and confirm it produced a file.

    Returns ``(ok, note, remedy)``. The capture is written to a temporary file
    that is deleted afterwards, and nothing it records is stored or shown -
    this proves the mechanism, it does not collect evidence.
    """
    device = _first_device_number(devices)
    if not device:
        return False, "no usable interface number in the TShark listing", (
            "Run 'tshark -D' manually to see what the driver reports."
        )

    handle, temp_name = tempfile.mkstemp(prefix="aethra-capture-probe-", suffix=".pcapng")
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        completed = _run(
            [
                str(executable),
                "-i", device,
                "-a", f"duration:{CAPTURE_PROBE_SECONDS}",
                "-w", str(temp_path),
                "-q",
            ],
            timeout=CAPTURE_PROBE_SECONDS + 30,
        )
    except subprocess.TimeoutExpired:
        return False, "the capture did not stop within its timeout", (
            "TShark started but would not exit. Check for a stuck dumpcap.exe."
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc), "Check that TShark and dumpcap are both installed."
    finally:
        # Give Windows a moment to release the handle before deleting.
        time.sleep(0.05)

    try:
        size = temp_path.stat().st_size if temp_path.exists() else -1
    except OSError:
        size = -1
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            LOGGER.debug("Could not delete the capture probe file %s.", temp_path)

    if completed.returncode != 0:
        note = _first_line(completed) or f"exit code {completed.returncode}"
        remedy = (
            "Install the Npcap driver and run as Administrator. On Windows, "
            "capture permission is granted by the driver, not by the account."
        )
        if "permission" in note.lower() or "denied" in note.lower():
            remedy = "Run AETHRA-SEC as Administrator; the driver refused access."
        return False, note, remedy

    if size <= 0:
        # A pcapng file always carries a section header, even with no packets,
        # so a zero-length file means the write itself failed.
        return False, "the capture file was empty, so nothing was written", (
            "Check that the temporary directory is writable."
        )
    return True, f"{size} bytes written in {CAPTURE_PROBE_SECONDS}s", ""


def _first_device_number(devices: list[str]) -> str:
    """The interface number from the first usable line of ``tshark -D``.

    Lines look like ``1. \\Device\\NPF_{GUID} (Ethernet)``. The number is used
    rather than the device name because it needs no quoting and TShark accepts
    it on every platform. Loopback is skipped when anything else is offered:
    proving capture works on a real adapter is the useful answer.
    """
    fallback = ""
    for line in devices:
        number, _, remainder = line.partition(".")
        number = number.strip()
        if not number.isdigit():
            continue
        lowered = remainder.lower()
        if "loopback" in lowered or "npf_loopback" in lowered:
            fallback = fallback or number
            continue
        return number
    return fallback


def probe_pyshark() -> ProbeResult:
    """Verify that the PyShark library imports and exposes a live capture."""
    result = ProbeResult("PyShark", False, "")
    try:
        import pyshark
    except Exception as exc:  # noqa: BLE001
        result.add("import pyshark", False, str(exc))
        result.detail = f"The PyShark library is not usable: {exc}"
        result.remedy = "Reinstall AETHRA-SEC, or run: pip install pyshark"
        return result
    result.add("import pyshark", True)

    if not hasattr(pyshark, "LiveCapture"):
        result.add("LiveCapture available", False)
        result.detail = "PyShark imported but does not provide LiveCapture."
        result.remedy = "Install a supported PyShark release: pip install 'pyshark>=0.6'"
        return result
    result.add("LiveCapture available", True)

    # PyShark does not expose __version__, so the installed distribution is
    # what actually answers the question.
    try:
        from importlib.metadata import version as _distribution_version

        result.version = _distribution_version("pyshark")
    except Exception:  # noqa: BLE001
        result.version = str(getattr(pyshark, "__version__", "") or "unknown version")
    result.passed = True
    result.detail = f"PyShark {result.version} imported; LiveCapture available."
    return result


# ---------------------------------------------------------------------------
# Snort
# ---------------------------------------------------------------------------
def probe_snort(
    configured_path: Path | None = None,
    configuration: Path | None = None,
) -> ProbeResult:
    """Verify Snort without starting a sensor or producing an alert.

    AETHRA-SEC never runs Snort itself - the sensor is operated separately and
    AETHRA-SEC reads what it produced. So this checks that the binary exists
    and reports a version, and, when a configuration file is supplied, runs
    ``snort -T -c <config>``: Snort's own self-test, which parses the
    configuration and every rule file it includes and then exits. It opens no
    interface in capture mode and writes no alert.

    A missing Snort is reported as ``SNORT UNAVAILABLE``. It is never reported
    as running.
    """
    from aethra_sec.utils.net import find_executable

    result = ProbeResult("Snort", False, "")

    executable = find_executable(
        configured_path,
        "snort",
        "snort.exe",
        extra_dirs=(
            Path(r"C:\Snort\bin"),
            Path(r"C:\Snort"),
            Path("/usr/sbin"),
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ),
    )
    if executable is None:
        result.add("locate snort", False)
        result.detail = "SNORT UNAVAILABLE - the executable was not found."
        result.remedy = (
            "Snort is optional. Install it from https://www.snort.org/downloads "
            "and point AETHRA-SEC at its alert output, or leave Snort ingest "
            "disabled - AETHRA-SEC's own detection rules keep working."
        )
        return result
    result.path = str(executable)
    result.add("locate snort", True, str(executable))

    try:
        version_run = _run([str(executable), "-V"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("snort -V", False, str(exc))
        result.detail = f"Snort was found at {executable} but could not run: {exc}"
        result.remedy = (
            "On Windows the usual cause is a missing runtime DLL - Snort needs "
            "Npcap and the Visual C++ runtime installed alongside it."
        )
        return result
    result.version = _snort_version(version_run)
    if not result.version:
        note = _first_line(version_run) or f"exit code {version_run.returncode}"
        result.add("snort -V", False, note)
        # Naming the file matters here: the usual cause is that the path points
        # at a wrapper, a WSL shim or a partially-installed build, and an
        # operator cannot tell which without knowing what was actually run.
        result.detail = (
            f"SNORT UNAVAILABLE - {executable} ran but reported no version "
            f"({note})."
        )
        result.remedy = (
            "Check that this really is the Snort executable. On Windows, Snort "
            "also needs Npcap and the Visual C++ runtime; a Snort that runs "
            "under WSL cannot be started as a Windows program - point "
            "AETHRA-SEC at its alert file instead."
        )
        return result
    result.add("snort -V", True, result.version)

    if configuration is None:
        result.passed = True
        result.detail = (
            f"{result.version} at {executable}. No configuration file is set, "
            "so the rules were not validated."
        )
        result.remedy = (
            "Set the Snort configuration path to have the rules validated here."
        )
        return result

    config_path = Path(configuration).expanduser()
    if not config_path.is_file():
        result.add("configuration file", False, str(config_path))
        result.detail = f"The configured Snort configuration is missing: {config_path}"
        result.remedy = "Correct the Snort configuration path, or clear it."
        return result
    result.add("configuration file", True, str(config_path))

    try:
        test_run = _run([str(executable), "-T", "-c", str(config_path)])
    except subprocess.TimeoutExpired:
        result.add("snort -T", False, "timed out")
        result.detail = "Snort's configuration test did not finish in time."
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        result.add("snort -T", False, str(exc))
        result.detail = f"Snort's configuration test could not run: {exc}"
        return result

    if test_run.returncode != 0:
        note = _snort_error(test_run)
        result.add("snort -T", False, note)
        result.detail = f"Snort rejected its configuration: {note}"
        result.remedy = (
            "Fix the configuration or the rule files it includes, then re-run "
            f"the check. Snort's own command is: snort -T -c {config_path}"
        )
        return result
    result.add("snort -T", True, "configuration and rules validated")

    result.passed = True
    result.detail = (
        f"{result.version} at {executable}; configuration and rules validated."
    )
    return result


def _snort_version(completed: subprocess.CompletedProcess[str]) -> str:
    """Pull the version out of Snort's banner, which spans several lines."""
    text = (completed.stdout or "") + (completed.stderr or "")
    for line in text.splitlines():
        stripped = line.strip(" ,*'\"")
        if "version" in stripped.lower() and any(ch.isdigit() for ch in stripped):
            return stripped
    return ""


def _snort_error(completed: subprocess.CompletedProcess[str]) -> str:
    """The most useful line of a failed ``snort -T``."""
    text = (completed.stdout or "") + (completed.stderr or "")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if "error" in line.lower() or "fatal" in line.lower():
            return line[:200]
    return (lines[-1][:200] if lines else f"exit code {completed.returncode}")


# ---------------------------------------------------------------------------
# Supporting checks
# ---------------------------------------------------------------------------
def probe_npcap() -> ProbeResult:
    """Report whether a Windows packet driver is present.

    Not a pass/fail gate of its own on other platforms - it is Windows that
    needs a separate driver - but on Windows it is the single most common
    reason capture does not work, and naming it directly saves an operator
    from diagnosing TShark instead.
    """
    result = ProbeResult("Packet driver", False, "")
    if os.name != "nt":
        result.passed = True
        result.detail = "Not applicable on this platform."
        result.add("platform", True, os.name)
        return result

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = (
        system_root / "System32" / "Npcap" / "wpcap.dll",
        system_root / "SysWOW64" / "Npcap" / "wpcap.dll",
        system_root / "System32" / "wpcap.dll",
    )
    for candidate in candidates:
        if candidate.is_file():
            result.passed = True
            result.path = str(candidate)
            result.detail = f"Packet driver present ({candidate})."
            result.add("locate wpcap.dll", True, str(candidate))
            return result

    result.add("locate wpcap.dll", False)
    result.detail = "No Npcap/WinPcap driver was found."
    result.remedy = (
        "Install Npcap from https://npcap.com/#download, or reinstall "
        "Wireshark and keep the Npcap component selected. Live capture "
        "cannot work without it."
    )
    return result


def probe_database(settings: object) -> ProbeResult:
    """Open a real connection and run a real query.

    A reachable server with wrong credentials, a missing schema and a firewall
    all look identical from a configuration file, so this connects.
    """
    from aethra_sec.core.errors import AethraError
    from aethra_sec.database.connection import DatabaseManager

    result = ProbeResult("Database", False, "")
    database = getattr(settings, "database", settings)
    target = (
        f"{getattr(database, 'user', '?')}@{getattr(database, 'host', '?')}:"
        f"{getattr(database, 'port', '?')}/{getattr(database, 'database', '?')}"
    )

    manager: DatabaseManager | None = None
    try:
        manager = DatabaseManager(database)
        row = manager.query_one("SELECT VERSION() AS version")
        version = str((row or {}).get("version", "")).strip()
    except AethraError as exc:
        result.add("connect", False, exc.user_message)
        result.detail = f"DATABASE UNAVAILABLE - {exc.user_message}"
        result.remedy = _database_remedy(exc.user_message)
        return result
    except Exception as exc:  # noqa: BLE001
        result.add("connect", False, str(exc))
        result.detail = f"DATABASE UNAVAILABLE - {exc}"
        result.remedy = _database_remedy(str(exc))
        return result
    finally:
        if manager is not None:
            try:
                manager.close()
            except Exception:  # noqa: BLE001
                pass

    result.add("connect", True, target)
    result.add("SELECT VERSION()", True, version or "no version reported")
    result.passed = True
    result.version = version
    result.detail = f"Connected to {target} (MySQL {version})."
    return result


def _database_remedy(message: str) -> str:
    """Turn a driver error into the thing the operator should actually do."""
    lowered = message.lower()
    if "access denied" in lowered or "authentication" in lowered:
        return (
            "The server is reachable but rejected the credentials. Check the "
            "database user and password in the setup wizard."
        )
    if "unknown database" in lowered:
        return (
            "The server is reachable but the database does not exist. The "
            "setup wizard can create it if the account has permission."
        )
    if "can't connect" in lowered or "refused" in lowered or "timed out" in lowered:
        return (
            "MySQL or MariaDB is not answering on that host and port. Start "
            "the service (XAMPP users: start MySQL in the control panel) and "
            "check the port."
        )
    return "Check the database host, port, user and password."


def find_mysql_client() -> Path | None:
    """Locate ``mysql``/``mysqldump`` for the backup feature, if installed."""
    for name in ("mysqldump", "mysqldump.exe"):
        found = shutil.which(name)
        if found:
            return Path(found)
    for directory in (
        Path(r"C:\xampp\mysql\bin"),
        Path(r"C:\Program Files\MySQL\MySQL Server 8.0\bin"),
        Path(r"C:\Program Files\MariaDB 11.4\bin"),
    ):
        candidate = directory / ("mysqldump.exe" if os.name == "nt" else "mysqldump")
        if candidate.is_file():
            return candidate
    return None
