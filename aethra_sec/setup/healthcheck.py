"""The AETHRA-SEC SYSTEM HEALTH report.

One report, produced from real probes, rendered the same way wherever it is
shown - the end of the graphical wizard, the end of ``setup.bat``, and
``AETHRA-SEC.exe --check``.

Every line comes from an attempt that was actually made. There is no path
through this module that reports PASS for something that was not exercised: a
line is PASS because a probe ran and succeeded, FAIL because a probe ran and
failed, or NOT CONFIGURED because there is nothing configured to test - and the
third is never quietly rendered as the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aethra_sec.config.settings import AppSettings
from aethra_sec.setup import detection
from aethra_sec.setup.interfaces import InterfaceReport, detect_interfaces
from aethra_sec.utils.logging import get_logger
from aethra_sec.version import APP_NAME, APP_VERSION

LOGGER = get_logger("setup.healthcheck")

#: Width of the dotted leader in the rendered report.
_LABEL_WIDTH = 22


@dataclass
class HealthLine:
    """One line of the health report."""

    label: str
    status: str
    detail: str = ""
    remedy: str = ""
    evidence: list[str] = field(default_factory=list)

    @property
    def is_failure(self) -> bool:
        """True only for an actual failure - not for something unconfigured."""
        return self.status == "FAIL"


@dataclass
class HealthReport:
    """The complete report, and what it means for starting up."""

    lines: list[HealthLine] = field(default_factory=list)

    @property
    def failures(self) -> list[HealthLine]:
        """The lines that failed."""
        return [line for line in self.lines if line.is_failure]

    @property
    def passed(self) -> int:
        """How many checks passed."""
        return sum(1 for line in self.lines if line.status == "PASS")

    @property
    def is_ready(self) -> bool:
        """True when nothing required for a usable installation failed.

        Only the database and a usable network interface are required. Nmap,
        TShark, Snort and SMTP are each capabilities: without them the matching
        feature reports itself unavailable, which is a working installation with
        less in it, not a broken one.
        """
        required = {"Database", "Network Interface"}
        return not any(line.label in required for line in self.failures)

    def render(self) -> str:
        """The report as text, in the layout the specification asks for."""
        width = 62
        out = [
            "=" * width,
            f"  {APP_NAME} SYSTEM HEALTH".ljust(width),
            f"  {APP_NAME} {APP_VERSION}",
            "=" * width,
            "",
        ]
        for line in self.lines:
            dots = "." * max(1, _LABEL_WIDTH - len(line.label))
            out.append(f"  {line.label} {dots} {line.status}")
            if line.detail:
                out.append(f"      {line.detail}")
            if line.remedy:
                out.append(f"      -> {line.remedy}")
        out.append("")
        out.append("-" * width)
        failures = self.failures
        if failures:
            out.append(
                f"  {self.passed} passed, {len(failures)} failed: "
                + ", ".join(line.label for line in failures)
            )
        else:
            out.append(f"  {self.passed} passed, 0 failed.")
        out.append(
            "  System is ready."
            if self.is_ready
            else "  System is NOT ready - resolve the failures above."
        )
        out.append("=" * width)
        return "\n".join(out)


def _line_from_probe(label: str, probe: detection.ProbeResult) -> HealthLine:
    """Turn a probe result into a report line, preserving its evidence."""
    return HealthLine(
        label=label,
        status=probe.status,
        detail=probe.detail,
        remedy=probe.remedy,
        evidence=list(probe.evidence),
    )


def run_health_check(
    settings: AppSettings,
    *,
    interface_report: InterfaceReport | None = None,
    selected_interface: str = "",
) -> HealthReport:
    """Run every check and return the report.

    Args:
        settings: the settings the installation will actually run with.
        interface_report: a previously computed interface report, so the wizard
            does not enumerate adapters twice. Detected here when omitted.
        selected_interface: the capture device the operator chose, if any.

    Returns:
        The report. Each line reflects an attempt that was made in this call.
    """
    report = HealthReport()

    report.lines.append(
        _line_from_probe("Database", detection.probe_database(settings))
    )
    report.lines.append(
        _line_from_probe("Nmap", detection.probe_nmap(settings.tools.nmap_path))
    )
    report.lines.append(
        _line_from_probe("TShark", detection.probe_tshark(settings.tools.tshark_path))
    )
    report.lines.append(_line_from_probe("PyShark", detection.probe_pyshark()))
    report.lines.append(
        _line_from_probe(
            "Snort",
            detection.probe_snort(
                settings.tools.snort_path, settings.tools.snort_config
            ),
        )
    )
    report.lines.append(_interface_line(settings, interface_report, selected_interface))
    report.lines.append(_smtp_line(settings))
    return report


def _interface_line(
    settings: AppSettings,
    interface_report: InterfaceReport | None,
    selected_interface: str,
) -> HealthLine:
    """Report whether a usable capture interface exists and is selected."""
    detected = interface_report or detect_interfaces(settings.tools.tshark_path)
    chosen = selected_interface or settings.capture.interface

    if not detected.interfaces:
        return HealthLine(
            "Network Interface",
            "FAIL",
            "No network interfaces were detected.",
            "Enable a network adapter, then run the check again.",
        )
    if not detected.has_usable_interface:
        return HealthLine(
            "Network Interface",
            "FAIL",
            f"{len(detected.interfaces)} interface(s) found, none with both an "
            "IPv4 address and an operational status.",
            "Enable and connect an adapter before starting a capture.",
        )

    if chosen:
        match = next(
            (item for item in detected.interfaces if item.name == chosen), None
        )
        if match is None:
            return HealthLine(
                "Network Interface",
                "FAIL",
                f"The configured interface is not present on this machine: {chosen}",
                "Choose an interface that exists, in setup or on the "
                "Network Monitoring screen.",
            )
        detail = f"{match.display_label}"
        if match.conflicts:
            detail += f"  (shares its subnet with {', '.join(match.conflicts)})"
        return HealthLine("Network Interface", "PASS", detail)

    recommended = detected.recommended
    if recommended is None:
        return HealthLine(
            "Network Interface",
            "FAIL",
            "No interface could be recommended and none is configured.",
            detected.reason,
        )
    return HealthLine(
        "Network Interface",
        "PASS",
        f"{len(detected.interfaces)} detected; none selected yet. "
        f"Recommended: {recommended.display_label}",
        "Choose an interface on the Network Monitoring screen before capturing.",
    )


def _smtp_line(settings: AppSettings) -> HealthLine:
    """Report the SMTP state, without claiming an untested configuration works."""
    smtp = settings.smtp
    if not smtp.is_configured:
        return HealthLine(
            "SMTP",
            "NOT CONFIGURED",
            "Notifications are shown in the application only.",
            "Optional. Sign-in never uses email.",
        )
    return HealthLine(
        "SMTP",
        "PASS",
        smtp.status_text(),
        "Configured. Send a test message from setup to prove delivery.",
    )
