"""Capture-filter validation (§50).

A BPF expression is compiled by libpcap against the link-layer type of a
specific interface, so the only honest way to know whether a filter is usable
is to ask the capture tool to compile it for that interface.

This matters because PyShark does not report the rejection. Given an invalid
filter, ``sniff_continuously()`` simply yields nothing: dumpcap exits, the
reader thread stays alive waiting for packets that will never arrive, and the
console reported CAPTURING while recording nothing. Validating before the
capture starts turns that silent dead end into a stated failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from aethra_sec.integrations.pyshark_capture.interfaces import find_tshark
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.pyshark.filters")

#: Seconds to let the probe run. It stops at the first packet or this limit,
#: whichever comes first, so a quiet interface still returns promptly.
PROBE_SECONDS = 1

#: Ceiling on the whole probe, so a wedged capture tool cannot hang a sign-in.
PROBE_TIMEOUT = 20


def _dumpcap_for(tshark_path: Path | str | None) -> Path | None:
    """The dumpcap that ships beside ``tshark``.

    dumpcap is what actually opens the interface and compiles the filter, and
    it is always installed alongside tshark.

    The configured path is usually empty - the application finds Wireshark for
    itself rather than making the operator type a path - so discovery is run
    here too. Without it the check would go looking for dumpcap on PATH, not
    find it (Wireshark's installer does not add itself), and quietly return
    "inconclusive" on every machine.
    """
    resolved = find_tshark(Path(tshark_path) if tshark_path else None)
    if resolved:
        candidate = resolved.with_name(
            "dumpcap.exe" if os.name == "nt" else "dumpcap"
        )
        if candidate.is_file():
            return candidate

    found = shutil.which("dumpcap")
    return Path(found) if found else None


def _readable_reason(stderr: str) -> str:
    """Turn dumpcap's rejection into one safe sentence.

    Only the parser's own explanation is kept. The command line, the executable
    path and the device identifier are dropped: none of them help the operator
    correct a filter, and the first two are internals.
    """
    for line in (stderr or "").splitlines():
        text = line.strip()
        lowered = text.lower()
        if "can't parse filter expression" in lowered:
            # e.g. "(can't parse filter expression: syntax error)"
            _, _, detail = text.partition("can't parse filter expression:")
            cleaned = detail.strip().rstrip(").")
            if cleaned:
                return f"the expression could not be parsed ({cleaned})"
            return "the expression could not be parsed"
        if "isn't a valid capture filter" in lowered:
            return "the expression is not a valid capture filter"
    return "the capture tool rejected it"


def validate_capture_filter(
    interface: str, bpf_filter: str, tshark_path: Path | str | None = None
) -> tuple[bool, str]:
    """Check that ``bpf_filter`` compiles for ``interface``.

    Args:
        interface: the capture device the filter will be used on.
        bpf_filter: the expression to check. Empty means "capture everything",
            which is always valid.
        tshark_path: the configured tshark, used to locate dumpcap beside it.

    Returns:
        ``(ok, message)``. When ``ok`` is False, ``message`` is safe to show:
        it names the filter and the parser's reason, and nothing internal.

        An inconclusive check - dumpcap missing, or the probe timing out -
        returns True. This validates filters; it is not a second opinion on
        whether capture can start, and refusing a sign-in because a *check*
        could not run would be its own failure. A capture that then fails for
        real is still caught by the liveness check after start-up.
    """
    expression = (bpf_filter or "").strip()
    if not expression:
        return True, ""

    dumpcap = _dumpcap_for(tshark_path)
    if dumpcap is None:
        LOGGER.debug("dumpcap not found; capture filter left unchecked.")
        return True, ""

    command = [
        str(dumpcap),
        "-i", interface,
        "-f", expression,
        "-c", "1",
        "-a", f"duration:{PROBE_SECONDS}",
        "-w", os.devnull,
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.debug("Capture filter check could not run: %s", exc)
        return True, ""

    if completed.returncode == 0:
        return True, ""

    stderr = completed.stderr or ""
    lowered = stderr.lower()

    # Distinguish a bad filter from a problem opening the interface. Only the
    # former is this function's business; the latter is reported by the start
    # itself, with its own guidance.
    if "capture filter" in lowered or "filter expression" in lowered:
        return False, (
            f"Capture filter rejected: {_readable_reason(stderr)}. "
            "Fix the expression and try again."
        )

    LOGGER.debug("Filter probe failed for a non-filter reason: %s", stderr[:200])
    return True, ""
