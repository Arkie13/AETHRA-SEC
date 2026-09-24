"""Turn a stored record into the sections a details drawer renders.

Two screens need to answer "what is this device?" without leaving the page -
the host inventory and an assessment result - and they must answer it
identically. The shaping lives here so the drawer widget
stays free of domain knowledge and the callers cannot drift apart.

Every value comes from a record the services returned. Where the record holds
nothing, the line says so; nothing here substitutes a plausible-looking value.
"""

from __future__ import annotations

from typing import Any

from aethra_sec.models.host import Host
from aethra_sec.models.scan import PortResult, ScanFinding, ScanHostResult
from aethra_sec.ui.widgets.drawer import DrawerSection
from aethra_sec.utils.formatting import format_bytes, format_count
from aethra_sec.utils.timeutil import format_local

#: Shown where a record genuinely holds no value for a field.
_UNKNOWN = "not recorded"


def _or_unknown(value: Any, unknown: str = _UNKNOWN) -> str:
    """The value as text, or a stated absence."""
    text = str(value or "").strip()
    return text or unknown


def host_chips(host: Host) -> list[tuple[str, str]]:
    """Header chips for a host: its risk and its status."""
    return [(str(host.risk_level), "severity"), (str(host.status), "state")]


def host_sections(detail: dict[str, Any]) -> list[DrawerSection]:
    """Sections describing one host, from ``HostService.detail``.

    Args:
        detail: the bundle the host service returns - the host itself plus its
            observations, ports, findings, scans and alerts.
    """
    host: Host | None = detail.get("host")
    if host is None:
        return [DrawerSection("Host", text="That host is no longer in the inventory.")]

    observations = detail.get("observations", [])
    ports = detail.get("open_ports", [])
    findings = detail.get("findings", [])
    alerts = detail.get("alerts", [])
    scans = detail.get("scans", [])

    identity = DrawerSection(
        "Identity",
        rows=[
            ("IP address", host.ip_address),
            ("Hostname", host.hostname_text),
            # The identity column says only "Unknown"; here is which absence
            # it is - a lookup that came back empty, or one never made.
            ("Hostname lookup", host.hostname_lookup_text),
            ("MAC address", _or_unknown(host.mac_address, "not observed")),
            ("Vendor", _or_unknown(host.vendor, "not identified")),
            ("Operating system", host.os_text),
            ("Status", str(host.status)),
            ("Risk level", str(host.risk_level)),
            ("Discovered by", host.discovery_source.label),
            (
                "Discovery evidence",
                host.discovery_detail or "not recorded for this row",
            ),
            (
                "Discovered on",
                host.discovery_interface or "not recorded for this row",
            ),
            (
                "Trusted asset",
                f"yes - {host.trust_note}" if host.is_trusted else "no",
            ),
            ("First seen", format_local(host.first_seen)),
            ("Last seen", format_local(host.last_seen)),
            (
                "Protocols",
                ", ".join(host.protocols_observed) or "none observed",
            ),
        ],
    )

    sections = [identity]

    if observations:
        sent = sum(o.packets_sent for o in observations)
        received = sum(o.packets_received for o in observations)
        sections.append(
            DrawerSection(
                "Observed traffic",
                subtitle="from live capture",
                rows=[
                    ("Packets sent", format_count(sent)),
                    ("Packets received", format_count(received)),
                    (
                        "Bytes sent",
                        format_bytes(sum(o.bytes_sent for o in observations)),
                    ),
                    (
                        "Bytes received",
                        format_bytes(sum(o.bytes_received for o in observations)),
                    ),
                ],
            )
        )

    sections.append(
        DrawerSection(
            f"Open ports ({len(ports)})",
            subtitle="from the most recent assessment",
            text=(
                "\n".join(
                    f"{port.endpoint:<12} {port.state:<8} {port.service_text}"
                    for port in ports[:40]
                )
                if ports
                else "No assessment has recorded open ports for this host."
            ),
        )
    )

    sections.append(
        DrawerSection(
            f"Vulnerability findings ({len(findings)})",
            text=(
                "\n".join(
                    f"[{finding.risk_level}] {finding.title}\n"
                    f"    {finding.observation}"
                    for finding in findings[:20]
                )
                if findings
                else "No findings are recorded for this host."
            ),
        )
    )

    sections.append(
        DrawerSection(
            f"Related alerts ({len(alerts)})",
            text=(
                "\n".join(
                    f"{format_local(alert.effective_time)}  [{alert.severity}] "
                    f"{alert.signature_text} {alert.message}"
                    for alert in alerts[:20]
                )
                if alerts
                else "No IDS alerts involve this host."
            ),
        )
    )

    if scans:
        sections.append(
            DrawerSection(
                f"Assessment history ({len(scans)})",
                text="\n".join(
                    f"scan {scan.id}  {format_local(scan.created_at)}  "
                    f"{scan.profile_label or scan.profile}  {scan.status}"
                    for scan in scans[:10]
                ),
            )
        )

    return sections


def port_chips(port: PortResult, finding: ScanFinding | None) -> list[tuple[str, str]]:
    """Header chips for one port: its state and the risk raised from it."""
    chips = [(port.state.upper(), "state")]
    if finding is not None:
        chips.insert(0, (str(finding.risk_level), "severity"))
    return chips


def port_sections(
    port: PortResult, finding: ScanFinding | None
) -> list[DrawerSection]:
    """Everything this scan recorded about one port.

    The port and the finding derived from it are shown together because that
    is the question an operator is actually asking - not "what is on 445" and
    separately "why does 445 matter", but both at once.
    """
    sections = [
        DrawerSection(
            "Port",
            subtitle="exactly as Nmap reported it",
            rows=[
                ("Port", f"{port.port}/{port.protocol.upper()}"),
                ("State", port.state.upper()),
                ("Reason", _or_unknown(port.reason, "not recorded")),
                ("Service", _or_unknown(port.service, "not identified")),
                ("Product", _or_unknown(port.product, "no banner")),
                ("Version", _or_unknown(port.version, "not detected")),
                ("Extra information", _or_unknown(port.extra_info, "-")),
                ("CPE", _or_unknown(port.cpe, "-")),
                ("Tunnel", _or_unknown(port.tunnel, "none")),
            ],
        )
    ]
    if finding is None:
        sections.append(
            DrawerSection(
                "Finding",
                text=(
                    "No finding was raised for this port.\n\n"
                    "An open port is not automatically a vulnerability. This "
                    "one matched no configured knowledge entry and no rule "
                    "the risk engine applies, so nothing is claimed about it."
                    if port.is_open
                    else "This port is not open, so no finding applies to it."
                ),
            )
        )
        return sections

    sections.append(
        DrawerSection(
            f"Finding · {finding.risk_level}",
            rows=[
                ("Title", finding.title),
                ("Risk level", str(finding.risk_level)),
                ("Status", finding.status_text),
                ("Reference", _or_unknown(finding.reference_text, "none recorded")),
            ],
        )
    )
    sections.append(
        DrawerSection(
            "Why this matters",
            text="\n\n".join(
                part
                for part in (
                    f"Observed: {finding.observation}" if finding.observation else "",
                    f"Concern: {finding.concern}" if finding.concern else "",
                    f"Risk rationale: {finding.risk_rationale}"
                    if finding.risk_rationale
                    else "",
                )
                if part
            )
            or "No further explanation was recorded for this finding.",
        )
    )
    return sections


def scan_host_chips(host: ScanHostResult) -> list[tuple[str, str]]:
    """Header chips for a scanned host: its highest finding risk and status."""
    return [(str(host.highest_risk), "severity"), (str(host.status), "state")]


def scan_host_sections(host: ScanHostResult, os_text: str) -> list[DrawerSection]:
    """Sections describing one host inside an assessment result.

    This is the scan's own record of the host - what *that run* observed - so it
    is kept separate from the inventory view even where the two overlap.
    """
    open_ports = host.open_ports
    sections = [
        DrawerSection(
            "Identity",
            subtitle="as recorded by this assessment",
            rows=[
                ("IP address", host.ip_address),
                ("Hostname", host.hostname_text),
                ("Hostname source", _or_unknown(host.hostname_source, "-")),
                ("MAC address", _or_unknown(host.mac_address, "not observed")),
                ("Vendor", _or_unknown(host.vendor, "not identified")),
                ("Operating system", os_text),
                ("OS source", _or_unknown(host.os_source, "-")),
                ("OS CPE", _or_unknown(host.os_cpe, "-")),
                ("Status", str(host.status)),
                ("Open ports", str(len(open_ports))),
                ("Highest risk", str(host.highest_risk)),
            ],
        ),
        # Why a field says "Unknown" is as useful as the field itself: it is
        # the difference between "this host refuses to say" and "we were not
        # allowed to ask". Shown only when there is something to explain.
        *(
            [
                DrawerSection(
                    "Why identity is incomplete",
                    text="\n".join(host.identity_notes),
                )
            ]
            if host.identity_notes
            else []
        ),
        DrawerSection(
            f"Ports and services ({len(host.ports)})",
            text=(
                "\n".join(
                    f"{port.port}/{port.protocol:<5} {port.state:<8} "
                    f"{port.service or '-':<12} "
                    f"{(port.product + ' ' + port.version).strip() or '-'}"
                    for port in host.ports[:60]
                )
                if host.ports
                else "This scan recorded no ports for this host."
            ),
        ),
        DrawerSection(
            f"Findings ({len(host.findings)})",
            text=(
                "\n".join(
                    f"[{finding.risk_level}] {finding.title}\n"
                    f"    {finding.observation}\n"
                    f"    {finding.risk_rationale}"
                    for finding in host.findings[:20]
                )
                if host.findings
                else (
                    "This assessment derived no findings for this host. An open "
                    "port is an exposure to review, not automatically a finding."
                )
            ),
        ),
    ]
    return sections
