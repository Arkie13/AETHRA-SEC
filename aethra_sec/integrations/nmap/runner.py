"""Nmap execution through ``python-nmap``.

The runner does exactly one thing: run a real ``nmap`` process with a validated
argument list and hand back its real output. It never fabricates a result, and
when Nmap is missing it says so (§101) rather than substituting an internal
scanner.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aethra_sec.core.errors import ScanError, ToolUnavailableError
from aethra_sec.integrations.nmap.profiles import ScanRequest
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.nmap.runner")

#: Standard Windows installation directories checked when Nmap is not on PATH.
WINDOWS_NMAP_DIRS: tuple[Path, ...] = (
    Path(r"C:\Program Files (x86)\Nmap"),
    Path(r"C:\Program Files\Nmap"),
)

NMAP_MISSING_MESSAGE = (
    "Nmap is not available. Install/configure Nmap before running "
    "vulnerability assessments. Download it from https://nmap.org/download "
    "and, if it is installed somewhere unusual, set AETHRA_NMAP_PATH in .env "
    "to the full path of nmap.exe."
)

try:  # pragma: no cover - depends on the installation
    import nmap as python_nmap

    PYTHON_NMAP_AVAILABLE = True
    PYTHON_NMAP_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover
    python_nmap = None  # type: ignore[assignment]
    PYTHON_NMAP_AVAILABLE = False
    PYTHON_NMAP_IMPORT_ERROR = str(exc)


@dataclass(frozen=True)
class NmapAvailability:
    """Result of probing for a usable Nmap installation."""

    available: bool
    executable: str = ""
    version: str = ""
    detail: str = ""
    library_available: bool = PYTHON_NMAP_AVAILABLE

    @property
    def status_text(self) -> str:
        """Status shown on the dashboard and diagnostics screens."""
        return "AVAILABLE" if self.available else "NOT AVAILABLE"


def find_nmap(configured_path: Path | None = None) -> Path | None:
    """Locate the ``nmap`` executable.

    Search order: the configured path, ``PATH``, then the standard Windows
    installation directories.
    """
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        if candidate.is_dir():
            for name in ("nmap.exe", "nmap"):
                nested = candidate / name
                if nested.is_file():
                    return nested.resolve()

    for name in ("nmap", "nmap.exe"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    for directory in WINDOWS_NMAP_DIRS:
        candidate = directory / "nmap.exe"
        if candidate.is_file():
            return candidate.resolve()
    return None


def probe_nmap(configured_path: Path | None = None) -> NmapAvailability:
    """Check whether Nmap can actually be executed.

    Runs ``nmap --version`` with a fixed argument list (no shell) and reports
    the real version string.
    """
    if not PYTHON_NMAP_AVAILABLE:
        return NmapAvailability(
            available=False,
            detail=(
                f"The python-nmap library is not installed "
                f"({PYTHON_NMAP_IMPORT_ERROR}). Run: pip install python-nmap"
            ),
            library_available=False,
        )

    executable = find_nmap(configured_path)
    if executable is None:
        return NmapAvailability(available=False, detail=NMAP_MISSING_MESSAGE)

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [str(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return NmapAvailability(
            available=False,
            executable=str(executable),
            detail=f"Nmap was found at {executable} but could not be executed: {exc}",
        )

    if completed.returncode != 0:
        return NmapAvailability(
            available=False,
            executable=str(executable),
            detail=(
                f"'{executable} --version' exited with code "
                f"{completed.returncode}: {completed.stderr.strip()[:200]}"
            ),
        )

    version_line = (completed.stdout or "").strip().splitlines()
    version = version_line[0].strip() if version_line else "unknown version"
    return NmapAvailability(
        available=True,
        executable=str(executable),
        version=version,
        detail=f"{version} at {executable}",
    )


@dataclass
class NmapRunResult:
    """The raw outcome of one Nmap execution."""

    scan_data: dict[str, Any]
    command_line: str
    nmap_version: str
    duration_seconds: float
    stderr: str = ""


class NmapRunner:
    """Executes assessment scans on a worker thread.

    One runner handles one scan at a time; the service layer creates a runner
    per scan so the Stop control can target a specific run.
    """

    def __init__(self, configured_path: Path | None = None) -> None:
        """Create a runner bound to a specific (or discovered) Nmap binary."""
        self._configured_path = configured_path
        self._process_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._scanner: Any = None

    @property
    def is_cancelled(self) -> bool:
        """True once :meth:`cancel` has been called."""
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Request cancellation of the running scan.

        ``python-nmap`` runs Nmap synchronously, so cancellation takes effect
        when the current invocation returns; the service marks the scan
        CANCELLED and discards its results.
        """
        self._cancelled.set()

    def run(self, request: ScanRequest) -> NmapRunResult:
        """Execute a validated scan request.

        Args:
            request: a :class:`ScanRequest` built by
                :func:`aethra_sec.integrations.nmap.profiles.build_scan_request`.

        Returns:
            The parsed scan dictionary exactly as Nmap produced it.

        Raises:
            ToolUnavailableError: when Nmap or python-nmap is missing.
            ScanError: when Nmap ran but failed.
        """
        import time

        availability = probe_nmap(self._configured_path)
        if not availability.available:
            raise ToolUnavailableError(
                "Nmap", availability.detail, user_message=availability.detail
            )

        # python-nmap searches PATH for the executable; point it at the exact
        # binary we probed so a configured path is genuinely honoured.
        executable = Path(availability.executable)
        search_path = (str(executable),) if executable.is_file() else ("nmap",)

        try:
            scanner = python_nmap.PortScanner(nmap_search_path=search_path)
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailableError(
                "Nmap",
                str(exc),
                user_message=(
                    "Nmap could not be initialised. " + NMAP_MISSING_MESSAGE
                ),
            ) from exc

        with self._process_lock:
            self._scanner = scanner

        started = time.monotonic()
        arguments = request.argument_string
        LOGGER.info(
            "Starting Nmap: target=%s profile=%s arguments=%s",
            request.target,
            request.profile.key,
            arguments,
        )
        try:
            scanner.scan(hosts=request.target, arguments=arguments, sudo=False)
        except python_nmap.PortScannerError as exc:  # type: ignore[union-attr]
            message = str(exc).strip()
            LOGGER.error("Nmap failed: %s", message)
            raise ScanError(
                f"Nmap reported an error: {message}",
                user_message=self._explain_failure(message),
            ) from exc
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Unexpected failure while running Nmap")
            raise ScanError(
                f"Nmap could not be run: {exc}",
                user_message=(
                    "The assessment could not be completed. See the System "
                    f"Health screen for details. Error: {exc}"
                ),
            ) from exc
        finally:
            duration = time.monotonic() - started

        if self._cancelled.is_set():
            raise ScanError(
                "Scan cancelled by the operator.",
                user_message="The assessment was stopped.",
            )

        try:
            scan_data = dict(scanner._scan_result)  # noqa: SLF001 - library API
        except Exception:  # noqa: BLE001
            scan_data = {}

        command_line = ""
        version = availability.version
        try:
            command_line = str(scanner.command_line())
        except Exception:  # noqa: BLE001
            command_line = f"nmap {arguments} {request.target}"
        try:
            info = scanner.nmap_version()
            if info:
                version = f"Nmap {info[0]}.{info[1]}"
        except Exception:  # noqa: BLE001
            pass

        LOGGER.info(
            "Nmap finished in %.2fs: %s", duration, command_line
        )
        return NmapRunResult(
            scan_data=scan_data,
            command_line=command_line,
            nmap_version=version,
            duration_seconds=duration,
        )

    @staticmethod
    def _explain_failure(message: str) -> str:
        """Translate a raw Nmap error into actionable guidance."""
        lowered = message.lower()
        if "requires root privileges" in lowered or "operation not permitted" in lowered:
            return (
                "This scan profile requires raw-socket privileges. Restart "
                "AETHRA-SEC as Administrator (Windows) or as root (Linux), or "
                "choose a TCP connect profile such as 'Standard scan'."
            )
        if "failed to resolve" in lowered or "no such host" in lowered:
            return (
                "The target could not be resolved. Check the hostname or use "
                "an IP address."
            )
        if "npcap" in lowered or "winpcap" in lowered or "pcap" in lowered:
            return (
                "Nmap could not access the capture driver. Install Npcap "
                "(https://npcap.com) and restart AETHRA-SEC."
            )
        if "permission denied" in lowered:
            return (
                "Nmap was denied permission. Check that the account running "
                "AETHRA-SEC may execute Nmap and access the network."
            )
        return f"Nmap reported: {message[:300]}"


def nmap_environment_notes() -> list[str]:
    """Environment observations for the diagnostics screen."""
    notes: list[str] = []
    if os.name == "nt":  # pragma: no cover - platform specific
        notes.append(
            "On Windows, SYN/OS/UDP scan profiles need an elevated process and "
            "an installed Npcap driver."
        )
    else:
        notes.append(
            "On Linux, SYN/OS/UDP scan profiles need root or the CAP_NET_RAW "
            "capability on the nmap binary."
        )
    if not PYTHON_NMAP_AVAILABLE:
        notes.append(f"python-nmap import failed: {PYTHON_NMAP_IMPORT_ERROR}")
    return notes
