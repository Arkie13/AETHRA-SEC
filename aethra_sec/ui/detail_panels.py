"""Turn a stored record into the sections a details drawer renders.

Three screens need to answer "what is this device?" without leaving the page -
the incident investigation, the host inventory and an assessment result - and
they must answer it identically. The shaping lives here so the drawer widget
stays free of domain knowledge and the three callers cannot drift apart.

Every value comes from a record the services returned. Where the record holds
nothing, the line says so; nothing here substitutes a plausible-looking value.
"""

from __future__ import annotations

from typing import Any

from aethra_sec.models.host import Host
from aethra_sec.models.scan import ScanHostResult
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
            observations, ports, findings, scans, alerts and incidents.
    """
    host: Host | None = detail.get("host")
    if host is None:
        return [DrawerSection("Host", text="That host is no longer in the inventory.")]

    observations = detail.get("observations", [])
    ports = detail.get("open_ports", [])
    findings = detail.get("findings", [])
    alerts = detail.get("alerts", [])
    incidents = detail.get("incidents", [])
    scans = detail.get("scans", [])

    identity = DrawerSection(
        "Identity",
        rows=[
            ("IP address", host.ip_address),
            ("Hostname", host.hostname_text),
            ("MAC address", _or_unknown(host.mac_address, "not observed")),
            ("Vendor", _or_unknown(host.vendor, "not identified")),
            ("Operating system", host.os_text),
            ("Status", str(host.status)),
            ("Risk level", str(host.risk_level)),
            ("Discovered by", host.discovery_source.label),
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
            f"Related incidents ({len(incidents)})",
            text=(
                "\n".join(
                    f"{incident.reference}  [{incident.severity}] {incident.title}\n"
                    f"    evidence: {incident.source_label}"
                    for incident in incidents[:20]
                )
                if incidents
                else "No incidents involve this host."
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
                ("Hostname", _or_unknown(host.hostname, "not resolved")),
                ("MAC address", _or_unknown(host.mac_address, "not observed")),
                ("Vendor", _or_unknown(host.vendor, "not identified")),
                ("Operating system", os_text),
                ("Status", str(host.status)),
                ("Open ports", str(len(open_ports))),
                ("Highest risk", str(host.highest_risk)),
            ],
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


def incident_device_chips(device: dict[str, Any]) -> list[tuple[str, str]]:
    """Header chips for a device named by an incident's evidence."""
    chips: list[tuple[str, str]] = []
    if device.get("risk"):
        chips.append((str(device["risk"]), "severity"))
    if device.get("status"):
        chips.append((str(device["status"]), "state"))
    return chips


def unknown_device_sections(device: dict[str, Any]) -> list[DrawerSection]:
    """Sections for an address the host inventory has never seen.

    The incident named it, so it is real; the inventory simply holds nothing
    about it yet, and the drawer says exactly that rather than guessing.
    """
    return [
        DrawerSection(
            "Address",
            rows=[
                ("IP address", str(device.get("ip", ""))),
                ("Role in this incident", str(device.get("role", "-"))),
            ],
        ),
        DrawerSection(
            "Host inventory",
            text=(
                "This address is not in the host inventory, so no hostname, MAC "
                "address, operating system, port or risk information is stored "
                "for it.\n\n"
                "It will appear in the inventory once packet capture observes "
                "it or an authorised assessment reaches it."
            ),
        ),
    ]
