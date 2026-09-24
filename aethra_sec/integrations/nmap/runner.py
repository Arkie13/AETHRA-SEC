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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aethra_sec.core.errors import ScanError, ScanTimeoutError, ToolUnavailableError
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
    "and, if it is installed somewhere unusual, set AETHRA_NMAP_PATH in the "
    "configuration file "
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


def _parse_run_statistics(scan_data: dict[str, Any], raw_xml: str) -> dict[str, int]:
    """Nmap's own count of what it probed and what answered.

    Read from python-nmap's ``scanstats`` when present and otherwise from the
    XML's ``<hosts up= down= total=>`` element. This is the record of a target
    that was scanned and reported *down*: Nmap emits no ``<host>`` element for
    such a target, so without these counts a completed scan of an unreachable
    address is indistinguishable from a scan that found nothing to do.
    """
    stats: dict[str, int] = {}
    section = (scan_data.get("nmap") or {}).get("scanstats") or {}
    for source, key in (
        ("uphosts", "up"), ("downhosts", "down"), ("totalhosts", "total"),
    ):
        try:
            stats[key] = int(str(section.get(source, "")).strip())
        except (TypeError, ValueError):
            continue

    if len(stats) < 3 and raw_xml:
        import re

        match = re.search(
            r'<hosts\s+up="(\d+)"\s+down="(\d+)"\s+total="(\d+)"', raw_xml
        )
        if match:
            stats["up"] = int(match.group(1))
            stats["down"] = int(match.group(2))
            stats["total"] = int(match.group(3))
    return stats


@dataclass
class NmapRunResult:
    """The raw outcome of one Nmap execution."""

    scan_data: dict[str, Any]
    command_line: str
    nmap_version: str
    duration_seconds: float
    stderr: str = ""
    #: Nmap's own run statistics (``uphosts``/``downhosts``/``totalhosts``).
    #: These matter because a host Nmap reports *down* produces no ``<host>``
    #: element at all - python-nmap then hands back an empty ``scan`` section,
    #: and this is the only remaining evidence that the target was probed and
    #: did not answer. Without it a completed scan is indistinguishable from
    #: a scan that never ran.
    statistics: dict[str, int] = field(default_factory=dict)
    #: Nmap's own XML. ``python-nmap`` builds ``scan_data`` from this document
    #: and drops several fields on the way - the reply TTL, the service
    #: ``ostype`` attribute, and every service CPE but the last. Those are the
    #: fields that identify an operating system without raw-socket privileges,
    #: so the document is kept and read directly. See
    #: :mod:`aethra_sec.integrations.nmap.osfingerprint`.
    raw_xml: str = ""
    #: Addresses Nmap abandoned because ``--host-timeout`` expired. Nmap still
    #: reports such a host *up* and the run as a *success*, with whatever it had
    #: gathered before giving up - so without this, an unfinished scan reads
    #: exactly like a finished one that found nothing.
    timed_out_hosts: tuple[str, ...] = ()


def timed_out_hosts(raw_xml: str) -> tuple[str, ...]:
    """Addresses whose ``<host>`` element carries ``timedout="true"``.

    Read from Nmap's own XML, measured against a real run: a host-timeout
    produces ``<host starttime=.. endtime=.. timedout="true"><status
    state="up" .../>`` and ``exit="success"``. python-nmap discards the
    attribute, which is why the document is read here directly.
    """
    if not raw_xml or 'timedout="true"' not in raw_xml:
        return ()
    import re

    found: list[str] = []
    for match in re.finditer(r"<host\b([^>]*)>(.*?)</host>", raw_xml, re.DOTALL):
        if 'timedout="true"' not in match.group(1):
            continue
        address = re.search(
            r'<address\s+addr="([^"]+)"\s+addrtype="ipv[46]"', match.group(2)
        )
        found.append(address.group(1) if address else "")
    return tuple(found)


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
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def is_cancelled(self) -> bool:
        """True once :meth:`cancel` has been called."""
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Request cancellation of the running scan, and stop Nmap now.

        ``python-nmap``'s own ``scan()`` blocks inside ``communicate()`` and
        exposes no process handle, so a Stop pressed against it only took
        effect when Nmap finished on its own - which, for a stalled scan, could
        be never. The runner therefore starts the process itself and keeps the
        handle, so cancelling terminates the real process immediately.
        """
        self._cancelled.set()
        self._terminate()

    def _terminate(self) -> None:
        """Kill the Nmap child if one is running. Never raises."""
        with self._process_lock:
            process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            process.kill()
        except Exception:  # noqa: BLE001 - it may have exited between checks
            LOGGER.debug("Nmap process could not be killed.", exc_info=True)

    def run(self, request: ScanRequest, *, timeout_seconds: float = 0.0) -> NmapRunResult:
        """Execute a validated scan request.

        Args:
            request: a :class:`ScanRequest` built by
                :func:`aethra_sec.integrations.nmap.profiles.build_scan_request`.
            timeout_seconds: wall-clock limit for the whole Nmap process. Zero
                means no limit beyond Nmap's own ``--host-timeout``. When the
                limit passes the process is killed and
                :class:`~aethra_sec.core.errors.ScanTimeoutError` is raised, so
                a stalled scan can never hold a worker - and the host it was
                assessing - forever.

        Returns:
            The parsed scan dictionary exactly as Nmap produced it.

        Raises:
            ToolUnavailableError: when Nmap or python-nmap is missing.
            ScanTimeoutError: when the wall-clock limit passed.
            ScanError: when Nmap ran but failed, or was cancelled.
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

        arguments = request.argument_string
        # The same argument vector python-nmap builds, so the XML it parses is
        # exactly what its own scan() would have produced.
        import shlex

        argv = [
            str(getattr(scanner, "_nmap_path", "") or executable),
            "-oX", "-",
            *shlex.split(request.target),
            *shlex.split(arguments),
        ]
        LOGGER.info(
            "Starting Nmap: target=%s profile=%s arguments=%s timeout=%ss",
            request.target,
            request.profile.key,
            arguments,
            int(timeout_seconds) if timeout_seconds else "none",
        )

        started = time.monotonic()
        if self._cancelled.is_set():
            raise ScanError(
                "Scan cancelled by the operator.",
                user_message="The assessment was stopped.",
            )
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # No console window, and no shared console: a child attached
                # to ours would receive this process's console control events.
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            raise ScanError(
                f"Nmap could not be run: {exc}",
                user_message=(
                    "The assessment could not be completed because Nmap could "
                    f"not be started: {exc}"
                ),
            ) from exc

        with self._process_lock:
            self._process = process
        # If this console dies, the kernel kills Nmap with it rather than
        # leaving an orphaned scan running against the network.
        try:
            from aethra_sec.integrations.pyshark_capture.jobs import adopt

            adopt(process.pid)
        except Exception:  # noqa: BLE001 - hardening only
            LOGGER.debug("Could not adopt Nmap into the job.", exc_info=True)

        deadline = started + timeout_seconds if timeout_seconds > 0 else None
        stdout = b""
        stderr = b""
        timed_out = False
        try:
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    # Retrying communicate() after TimeoutExpired loses no
                    # output; this loop only exists to notice cancel/deadline.
                    if self._cancelled.is_set():
                        self._terminate()
                    elif deadline is not None and time.monotonic() >= deadline:
                        timed_out = True
                        self._terminate()
        finally:
            duration = time.monotonic() - started
            with self._process_lock:
                self._process = None

        if self._cancelled.is_set():
            raise ScanError(
                "Scan cancelled by the operator.",
                user_message="The assessment was stopped.",
            )
        if timed_out:
            LOGGER.warning(
                "Nmap exceeded its %.0fs limit for %s and was stopped.",
                timeout_seconds, request.target,
            )
            raise ScanTimeoutError(
                f"Nmap exceeded the {timeout_seconds:.0f}s assessment limit.",
                user_message=(
                    f"The assessment of {request.target} timed out: Nmap did "
                    f"not finish within {timeout_seconds:.0f} seconds and was "
                    "stopped. No result was recorded, because a scan that did "
                    "not finish says nothing about what the host exposes."
                ),
            )

        error_text = stderr.decode("utf-8", "replace") if stderr else ""
        warnings = [
            line + os.linesep
            for line in error_text.splitlines()
            if line.strip().lower().startswith("warning:")
        ]
        errors = [
            line + os.linesep
            for line in error_text.splitlines()
            if line.strip() and not line.strip().lower().startswith("warning:")
        ]
        try:
            scanner.analyse_nmap_xml_scan(
                nmap_xml_output=stdout,
                nmap_err=error_text,
                nmap_err_keep_trace=errors,
                nmap_warn_keep_trace=warnings,
            )
        except python_nmap.PortScannerError as exc:  # type: ignore[union-attr]
            message = str(exc).strip() or error_text.strip()
            LOGGER.error("Nmap failed (exit %s): %s", process.returncode, message)
            raise ScanError(
                f"Nmap reported an error: {message}",
                user_message=self._explain_failure(message),
            ) from exc
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Unexpected failure while reading Nmap output")
            raise ScanError(
                f"Nmap output could not be read: {exc}",
                user_message=(
                    "The assessment could not be completed: Nmap's output "
                    f"could not be read. Error: {exc}"
                ),
            ) from exc

        try:
            scan_data = dict(scanner._scan_result)  # noqa: SLF001 - library API
        except Exception:  # noqa: BLE001
            scan_data = {}

        raw_xml = stdout.decode("utf-8", "replace") if stdout else ""

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
            stderr=error_text,
            statistics=_parse_run_statistics(scan_data, raw_xml),
            raw_xml=raw_xml,
            timed_out_hosts=timed_out_hosts(raw_xml),
        )

    @staticmethod
    def _explain_failure(message: str) -> str:
        """Translate a raw Nmap error into actionable guidance."""
        lowered = message.lower()
        # python-nmap raises with the whole partial XML document when Nmap
        # exits before finishing. Showing that to an operator is unreadable
        # noise; what it actually means is that the scan never completed.
        if "<nmaprun" in lowered and "</nmaprun>" not in lowered:
            return (
                "Nmap started but did not finish, so no results were "
                "produced. This usually means the scan stalled on the "
                "network: probes may be leaving on an adapter that cannot "
                "reach the target when two adapters claim the same subnet. "
                "Choose the correct interface above and scan again."
            )
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


@dataclass(frozen=True)
class NmapInterface:
    """One interface as Nmap itself reports it, with its own route metric."""

    device: str
    address: str
    label: str
    #: Interfaces whose subnet another interface also claims. Nmap picks one
    #: of them by metric, and probes to that subnet leave on whichever it
    #: chose - which is silently wrong when the chosen one is virtual.
    ambiguous_subnet: bool = False


def _is_shareable_subnet(token: str) -> bool:
    """True for a unicast network where two adapters claiming it is a fault.

    Several routes legitimately exist on every interface - multicast
    (224.0.0.0/4), the limited broadcast address, link-local and loopback -
    and counting those would report every machine as misconfigured. Only a
    real, routable unicast network is a genuine clash.
    """
    import ipaddress

    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    if network.version != 4 or network.prefixlen in (0, 32):
        return False
    return not (
        network.is_multicast
        or network.is_loopback
        or network.is_link_local
        or network.is_reserved
    )


def _is_ipv4_cidr(token: str) -> bool:
    """True for a real IPv4 ``address/prefix`` token.

    Guards against the listing's own ``IP/MASK`` column header and against
    IPv6 entries: every adapter carries a link-local ``fe80::/64`` route, so
    counting those would report every interface as conflicting.
    """
    address, _, prefix = token.partition("/")
    if not prefix.isdigit() or ":" in token:
        return False
    octets = address.split(".")
    return len(octets) == 4 and all(o.isdigit() and int(o) < 256 for o in octets)


def _parse_iflist(output: str) -> tuple[list[NmapInterface], set[str]]:
    """Parse ``nmap --iflist`` into interfaces and duplicated subnets."""
    interfaces: list[NmapInterface] = []
    route_subnets: dict[str, set[str]] = {}
    section = ""

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        upper = line.upper()
        if "INTERFACES" in upper and line.startswith("*"):
            section = "if"
            continue
        if "ROUTES" in upper and line.startswith("*"):
            section = "routes"
            continue

        parts = line.split()
        if section == "if" and len(parts) >= 3 and _is_ipv4_cidr(parts[2]):
            device, address = parts[0], parts[2]
            interfaces.append(
                NmapInterface(
                    device=device,
                    address=address,
                    label=f"{device}  {address}",
                )
            )
        elif section == "routes" and len(parts) >= 2 and _is_ipv4_cidr(parts[0]):
            subnet, device = parts[0], parts[1]
            if _is_shareable_subnet(subnet):
                route_subnets.setdefault(subnet, set()).add(device)

    contested = {
        device
        for devices in route_subnets.values()
        if len(devices) > 1
        for device in devices
    }
    return (
        [
            NmapInterface(
                device=entry.device,
                address=entry.address,
                label=entry.label
                + ("   (subnet also claimed by another interface)"
                   if entry.device in contested else ""),
                ambiguous_subnet=entry.device in contested,
            )
            for entry in interfaces
        ],
        contested,
    )


def list_nmap_interfaces(
    configured_path: Path | None = None,
) -> tuple[NmapInterface, ...]:
    """Interfaces Nmap can send from, as Nmap itself lists them.

    Read from ``nmap --iflist`` rather than from the operating system, because
    it is Nmap's own view - and Nmap's own routing choice - that decides where
    a probe actually leaves from.
    """
    executable = find_nmap(configured_path)
    if executable is None:
        return ()
    try:
        completed = subprocess.run(
            [str(executable), "--iflist"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.debug("Could not list Nmap interfaces: %s", exc)
        return ()
    interfaces, _ = _parse_iflist(completed.stdout or "")
    return tuple(interfaces)


def contested_subnet_warning(
    configured_path: Path | None = None,
) -> str:
    """Explain a duplicate-subnet clash, when Nmap's routes show one.

    Two interfaces routing the same subnet is the condition where Nmap sends
    probes out an adapter that cannot reach the target - typically a virtual
    adapter (VMware/VirtualBox/WSL) configured with the same range as the real
    LAN - and reports a live host as down. It is worth naming, because no scan
    profile can work around it.
    """
    executable = find_nmap(configured_path)
    if executable is None:
        return ""
    try:
        completed = subprocess.run(
            [str(executable), "--iflist"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    interfaces, contested = _parse_iflist(completed.stdout or "")
    if not contested:
        return ""
    named = [entry for entry in interfaces if entry.device in contested]
    detail = "; ".join(f"{entry.device} ({entry.address})" for entry in named)
    return (
        "More than one adapter routes the same subnet - "
        f"{detail}. Left to itself Nmap picks one by route metric, which may "
        "be an adapter that cannot reach the target - a live host is then "
        "reported down. With Interface set to Automatic (route-based), "
        "AETHRA-SEC pins the probe to the adapter the operating system "
        "actually reaches the target through, preferring one that already has "
        "the target in its ARP cache. Choose an interface explicitly to "
        "override that."
    )


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
