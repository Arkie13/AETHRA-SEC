"""Parsing of real Nmap output into AETHRA-SEC models (§18, §19).

Two responsibilities, kept deliberately separate:

* :func:`parse_scan_result` records **observations** - exactly what Nmap said.
* :class:`FindingBuilder` derives **security findings** from those
  observations using documented rules, and states the reasoning.

The distinction matters: an open port is an observation, not a vulnerability.
A finding says what was observed, why it may matter, and how confident we are -
and it never invents a CVE identifier. When no configured vulnerability source
matched, the finding says "further vulnerability verification required" (§19).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel
from aethra_sec.models.scan import PortResult, ScanFinding, ScanHostResult
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import service_name_for_port

LOGGER = get_logger("integrations.nmap.parser")

# Matches identifiers that a *real* configured source (an NSE script such as
# `vulners`, or the administrator's vuln_knowledge table) may supply. Nothing
# here manufactures an identifier; the pattern only recognises one that Nmap
# actually printed.
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass(frozen=True)
class VulnKnowledgeEntry:
    """One administrator-configured vulnerability knowledge row.

    This is the "configured vulnerability source" referred to in §19. The
    knowledge base is empty until an administrator populates it, and when it is
    empty AETHRA-SEC reports exposure without claiming a specific vulnerability.
    """

    service: str
    product_pattern: str
    version_pattern: str
    port: int | None
    title: str
    concern: str
    risk_level: RiskLevel
    reference: str
    reference_source: str

    def matches(self, port: PortResult) -> bool:
        """True when this entry applies to an observed port."""
        if self.service and self.service.lower() != (port.service or "").lower():
            return False
        if self.port is not None and self.port != port.port:
            return False
        if self.product_pattern:
            try:
                if not re.search(self.product_pattern, port.product or "", re.IGNORECASE):
                    return False
            except re.error:
                return False
        if self.version_pattern:
            try:
                if not re.search(self.version_pattern, port.version or "", re.IGNORECASE):
                    return False
            except re.error:
                return False
        return bool(self.service or self.product_pattern or self.port is not None)


def _text(value: Any) -> str:
    """Coerce an Nmap dictionary value to trimmed text."""
    if value is None:
        return ""
    return str(value).strip()


def _int_or_none(value: Any) -> int | None:
    """Coerce an Nmap dictionary value to ``int`` where possible."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_port_entry(
    port_number: Any, protocol: str, entry: dict[str, Any]
) -> PortResult | None:
    """Convert one Nmap port entry into a :class:`PortResult`.

    Returns ``None`` when the port number is unusable, which keeps one odd
    entry from discarding the whole host.
    """
    port = _int_or_none(port_number)
    if port is None or not 0 < port <= 65_535:
        return None
    service = _text(entry.get("name"))
    cpe = entry.get("cpe")
    if isinstance(cpe, (list, tuple)):
        cpe_text = ", ".join(_text(item) for item in cpe if _text(item))
    else:
        cpe_text = _text(cpe)
    return PortResult(
        port=port,
        protocol=(protocol or "tcp").lower(),
        state=_text(entry.get("state")).lower(),
        service=service,
        product=_text(entry.get("product")),
        version=_text(entry.get("version")),
        extra_info=_text(entry.get("extrainfo")),
        cpe=cpe_text,
        reason=_text(entry.get("reason")),
        tunnel=_text(entry.get("tunnel")),
    )


def _parse_os(host_entry: dict[str, Any]) -> tuple[str, int | None, str]:
    """Extract the best OS match Nmap reported.

    Returns:
        ``(os_name, accuracy, os_family)``; all empty when Nmap did not attempt
        or could not determine OS detection. Nothing is guessed.
    """
    matches = host_entry.get("osmatch") or []
    if not isinstance(matches, Sequence) or not matches:
        return "", None, ""
    best = matches[0]
    if not isinstance(best, dict):
        return "", None, ""
    name = _text(best.get("name"))
    accuracy = _int_or_none(best.get("accuracy"))
    family = ""
    classes = best.get("osclass") or []
    if isinstance(classes, Sequence) and classes and isinstance(classes[0], dict):
        family = _text(classes[0].get("osfamily"))
    return name, accuracy, family


def _parse_addresses(host_entry: dict[str, Any]) -> tuple[str, str, str]:
    """Extract IPv4/IPv6, MAC address and vendor from an Nmap host entry."""
    addresses = host_entry.get("addresses") or {}
    ip_address = _text(addresses.get("ipv4")) or _text(addresses.get("ipv6"))
    mac = _text(addresses.get("mac")).lower().replace("-", ":")
    vendor = ""
    vendors = host_entry.get("vendor") or {}
    if isinstance(vendors, dict) and mac:
        vendor = _text(vendors.get(mac.upper())) or _text(vendors.get(mac))
        if not vendor and vendors:
            vendor = _text(next(iter(vendors.values())))
    return ip_address, mac, vendor


def _parse_hostname(host_entry: dict[str, Any]) -> str:
    """Extract the hostname Nmap resolved.

    Returns an empty string when resolution failed - the UI then shows the IP
    address rather than an invented name (§15).
    """
    names = host_entry.get("hostnames") or []
    if isinstance(names, Sequence):
        for item in names:
            if isinstance(item, dict):
                candidate = _text(item.get("name"))
                if candidate:
                    return candidate
    return _text(host_entry.get("hostname"))


def parse_scan_result(scan_data: dict[str, Any]) -> list[ScanHostResult]:
    """Convert a ``python-nmap`` scan dictionary into host results.

    Args:
        scan_data: the ``_scan_result`` structure produced by python-nmap.

    Returns:
        One :class:`ScanHostResult` per host Nmap reported, in address order.
        An empty list means Nmap genuinely found nothing.
    """
    hosts_section = scan_data.get("scan") or {}
    if not isinstance(hosts_section, dict):
        return []

    results: list[ScanHostResult] = []
    for address, host_entry in hosts_section.items():
        if not isinstance(host_entry, dict):
            continue
        try:
            ip_address, mac, vendor = _parse_addresses(host_entry)
            ip_address = ip_address or _text(address)
            status_entry = host_entry.get("status") or {}
            state_text = _text(status_entry.get("state")).upper()
            status = (
                HostStatus.UP
                if state_text == "UP"
                else HostStatus.DOWN
                if state_text == "DOWN"
                else HostStatus.UNKNOWN
            )
            os_name, accuracy, family = _parse_os(host_entry)

            ports: list[PortResult] = []
            for protocol in ("tcp", "udp", "sctp"):
                protocol_section = host_entry.get(protocol) or {}
                if not isinstance(protocol_section, dict):
                    continue
                for port_number, entry in protocol_section.items():
                    if not isinstance(entry, dict):
                        continue
                    parsed = parse_port_entry(port_number, protocol, entry)
                    if parsed is not None:
                        ports.append(parsed)
            ports.sort(key=lambda p: (p.protocol, p.port))

            results.append(
                ScanHostResult(
                    ip_address=ip_address,
                    hostname=_parse_hostname(host_entry),
                    mac_address=mac,
                    vendor=vendor,
                    status=status,
                    os_name=os_name,
                    os_accuracy=accuracy,
                    os_family=family,
                    ports=ports,
                )
            )
        except Exception:  # noqa: BLE001 - one odd host must not lose the scan
            LOGGER.exception("Could not parse Nmap host entry for %s", address)

    results.sort(key=lambda h: h.ip_address)
    return results


def extract_script_references(host_entry: dict[str, Any]) -> dict[int, list[str]]:
    """Collect vulnerability identifiers printed by NSE scripts.

    Only identifiers that Nmap actually printed are returned. When no NSE
    script ran, the result is empty and findings say verification is required.
    """
    references: dict[int, list[str]] = {}
    for protocol in ("tcp", "udp"):
        section = host_entry.get(protocol) or {}
        if not isinstance(section, dict):
            continue
        for port_number, entry in section.items():
            port = _int_or_none(port_number)
            if port is None or not isinstance(entry, dict):
                continue
            scripts = entry.get("script") or {}
            if not isinstance(scripts, dict):
                continue
            found: list[str] = []
            for output in scripts.values():
                found.extend(
                    match.group(0).upper()
                    for match in _CVE_PATTERN.finditer(str(output))
                )
            if found:
                references[port] = sorted(set(found))
    return references


class FindingBuilder:
    """Derives explainable security findings from real scan observations."""

    def __init__(
        self,
        risk_engine: RiskEngine | None = None,
        knowledge: Iterable[VulnKnowledgeEntry] = (),
    ) -> None:
        """Create the builder.

        Args:
            risk_engine: scoring engine; a default one is created when omitted.
            knowledge: administrator-configured vulnerability knowledge. When
                empty, findings report exposure without asserting a specific
                vulnerability.
        """
        self._risk = risk_engine or RiskEngine()
        self._knowledge = tuple(knowledge)

    def build_for_host(
        self,
        host: ScanHostResult,
        *,
        scan_id: int | None = None,
        script_references: dict[int, list[str]] | None = None,
        host_is_trusted: bool = False,
    ) -> list[ScanFinding]:
        """Derive findings for one scanned host.

        Returns:
            A list of findings, most serious first. A host with no open ports
            produces no findings at all - silence is a valid, honest result.
        """
        findings: list[ScanFinding] = []
        references = script_references or {}

        for port in host.open_ports:
            knowledge_hit = next(
                (entry for entry in self._knowledge if entry.matches(port)), None
            )
            script_cves = references.get(port.port, [])

            reference = ""
            reference_source = ""
            if knowledge_hit:
                reference = knowledge_hit.reference
                reference_source = knowledge_hit.reference_source or "Configured knowledge base"
            elif script_cves:
                reference = ", ".join(script_cves[:5])
                reference_source = "Nmap NSE script output"

            risk_level, rationale = self._risk.score_exposure(
                service=port.service or service_name_for_port(port.port, port.protocol),
                port=port.port,
                product=port.product,
                version=port.version,
                has_known_vulnerability=bool(reference),
                host_is_trusted=host_is_trusted,
            )
            if knowledge_hit and knowledge_hit.risk_level.severity.rank > risk_level.severity.rank:
                risk_level = knowledge_hit.risk_level
                rationale += (
                    f" Raised to {risk_level} by the configured knowledge base "
                    f"entry '{knowledge_hit.title}'."
                )

            service_label = port.service or service_name_for_port(
                port.port, port.protocol
            ) or "unidentified service"
            observation = (
                f"Nmap reported {port.port}/{port.protocol} as OPEN on "
                f"{host.ip_address}"
                + (f", identified as '{service_label}'" if service_label else "")
                + (f" ({port.product} {port.version})".rstrip() if port.product else "")
                + "."
            )

            if knowledge_hit:
                concern = knowledge_hit.concern
                title = knowledge_hit.title
            else:
                title = f"{service_label} exposed on {port.port}/{port.protocol}"
                concern = (
                    f"The {service_label} service is reachable from the "
                    "scanning position. An open port is not automatically a "
                    "vulnerability: it identifies an exposed network service "
                    "whose necessity, access restrictions, configuration and "
                    "patch level should be reviewed."
                )

            evidence_parts = [
                f"state={port.state}",
                f"reason={port.reason or 'not reported'}",
            ]
            if port.product:
                evidence_parts.append(f"product={port.product}")
            if port.version:
                evidence_parts.append(f"version={port.version}")
            if port.extra_info:
                evidence_parts.append(f"extra={port.extra_info}")
            if port.cpe:
                evidence_parts.append(f"cpe={port.cpe}")
            if script_cves:
                evidence_parts.append(f"nse_references={', '.join(script_cves)}")

            findings.append(
                ScanFinding(
                    scan_id=scan_id,
                    scan_host_id=host.id,
                    host_id=host.host_id,
                    ip_address=host.ip_address,
                    port=port.port,
                    protocol=port.protocol,
                    service=port.service,
                    title=title[:190],
                    observation=observation,
                    concern=concern,
                    risk_level=risk_level,
                    risk_rationale=rationale,
                    evidence="; ".join(evidence_parts),
                    reference=reference,
                    reference_source=reference_source,
                    verification_required=not reference,
                    source=EvidenceSource.NMAP,
                )
            )

        cleartext_finding = self._cleartext_summary(host, scan_id)
        if cleartext_finding:
            findings.append(cleartext_finding)

        findings.sort(key=lambda f: f.risk_level.severity.rank, reverse=True)
        return findings

    def _cleartext_summary(
        self, host: ScanHostResult, scan_id: int | None
    ) -> ScanFinding | None:
        """Raise one finding when several unencrypted services are exposed.

        This is a documented correlation over the host's own observations, not
        an extra assumption about any single port.
        """
        from aethra_sec.analytics.risk_engine import CLEARTEXT_SERVICES

        cleartext = [
            p for p in host.open_ports if (p.service or "").lower() in CLEARTEXT_SERVICES
        ]
        if len(cleartext) < 2:
            return None
        listing = ", ".join(f"{p.port}/{p.protocol} ({p.service})" for p in cleartext)
        return ScanFinding(
            scan_id=scan_id,
            scan_host_id=host.id,
            host_id=host.host_id,
            ip_address=host.ip_address,
            port=None,
            protocol="",
            service="",
            title=f"Multiple unencrypted services exposed on {host.ip_address}",
            observation=(
                f"Nmap reported {len(cleartext)} services that transmit data "
                f"without encryption by default: {listing}."
            ),
            concern=(
                "Protocols in this group send credentials and data in "
                "cleartext. Anyone able to observe the traffic between client "
                "and server - including from a switch mirror port such as the "
                "one AETHRA-SEC monitors - can read it."
            ),
            risk_level=RiskLevel.MEDIUM,
            risk_rationale=(
                f"Risk MEDIUM: {len(cleartext)} cleartext services on a single "
                "host materially increases the value of intercepting this "
                "host's traffic."
            ),
            evidence=listing,
            reference="",
            reference_source="",
            verification_required=True,
            source=EvidenceSource.NMAP,
        )
