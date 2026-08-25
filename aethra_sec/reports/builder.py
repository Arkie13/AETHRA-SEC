"""Report assembly from real stored records (§48, §49, §95, §115).

A report is a set of sections, each a table of rows read straight from MySQL,
plus metadata naming who generated it, when, and over what period.

Nothing is estimated or rounded up into existence. A section with no records
renders "No records available" and the report says so in its conclusion, rather
than filling the page with plausible-looking numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Sequence

from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.models.enums import ReportType
from aethra_sec.utils.formatting import format_bytes, format_count, format_rate
from aethra_sec.utils.timeutil import format_local, utcnow
from aethra_sec.version import APP_FULL_NAME, APP_VERSION, AUTHORIZED_USE_NOTICE

NO_RECORDS_TEXT = "No records available for this section in the selected period."

#: Plain-language explanations included in reports for a student audience (§86).
EDUCATIONAL_NOTES: dict[str, str] = {
    "open_ports": (
        "An open port is not automatically a vulnerability. It indicates an "
        "exposed network service that should be reviewed: is it required, is "
        "it restricted to the networks that need it, and is it patched?"
    ),
    "findings": (
        "Findings are derived from what Nmap observed. Where no configured "
        "vulnerability source matched a service, the finding says that further "
        "verification is required rather than naming a specific weakness."
    ),
    "alerts": (
        "IDS alerts come from Snort signature matches. A signature match is "
        "evidence, not proof: signatures can match benign traffic, which is "
        "why analysts classify alerts as true or false positives."
    ),
    "anomalies": (
        "Traffic anomalies are threshold-based observations from live packet "
        "analysis. Each one records the value measured, the configured "
        "threshold and the time window, so the judgement can be audited."
    ),
    "incidents": (
        "An incident groups related evidence from one or more subsystems. The "
        "evidence source line states exactly which subsystems contributed - an "
        "incident supported by only one source says so."
    ),
    "traffic": (
        "Traffic figures are computed from packets actually captured on the "
        "monitored interface. A monitoring port only sees the traffic that "
        "reaches it, so a switch mirror/SPAN port is needed to observe traffic "
        "between other hosts."
    ),
}


@dataclass
class ReportSection:
    """One table in a report."""

    title: str
    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    note: str = ""
    summary: str = ""
    #: True when the rows are counts derived from stored records rather than
    #: the records themselves. Derived rows are excluded from the record total
    #: so a report over an empty database still reports zero records (§1).
    derived: bool = False

    @property
    def has_rows(self) -> bool:
        """False when the query returned nothing."""
        return bool(self.rows)

    @property
    def row_count(self) -> int:
        """Number of records in this section."""
        return len(self.rows)


@dataclass
class ReportDocument:
    """A complete report ready to be written to CSV, Excel or PDF."""

    report_type: ReportType
    title: str
    generated_at: datetime
    generated_by: str
    period_start: datetime
    period_end: datetime
    scope: str
    sections: list[ReportSection] = field(default_factory=list)
    highlights: list[tuple[str, str]] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    conclusion: str = ""

    @property
    def record_counts(self) -> dict[str, int]:
        """Row count per section, stored with the report metadata (§95)."""
        return {section.title: section.row_count for section in self.sections}

    @property
    def total_records(self) -> int:
        """Total stored records across every evidence section.

        Sections marked ``derived`` hold counts computed from those records
        (severity distributions, posture summaries) and are not counted, so an
        empty database yields a total of zero rather than a row of zeroes.
        """
        return sum(
            section.row_count for section in self.sections if not section.derived
        )

    @property
    def has_records(self) -> bool:
        """False when the report covers no records at all."""
        return self.total_records > 0

    def metadata_rows(self) -> list[tuple[str, str]]:
        """Report metadata shown at the top of every export."""
        return [
            ("System", APP_FULL_NAME),
            ("Version", APP_VERSION),
            ("Report", self.title),
            ("Generated at", format_local(self.generated_at)),
            ("Generated by", self.generated_by or "unknown"),
            ("Period start", format_local(self.period_start)),
            ("Period end", format_local(self.period_end)),
            ("Scope", self.scope),
            ("Total records", format_count(self.total_records)),
            ("Notice", AUTHORIZED_USE_NOTICE),
        ]


class ReportBuilder:
    """Builds each report type from stored records only."""

    def __init__(
        self,
        scans: ScanRepository,
        alerts: AlertRepository,
        incidents: IncidentRepository,
        hosts: HostRepository,
        traffic: TrafficRepository,
        audit: AuditRepository,
    ) -> None:
        """Bind the builder to the repositories it reads."""
        self._scans = scans
        self._alerts = alerts
        self._incidents = incidents
        self._hosts = hosts
        self._traffic = traffic
        self._audit = audit

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def build(
        self,
        report_type: ReportType,
        *,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        generated_by: str = "",
        scope: str = "All monitored assets",
        limit: int = 2000,
    ) -> ReportDocument:
        """Build a report of the requested type over the requested period."""
        end = period_end or utcnow()
        start = period_start or (end - timedelta(days=7))
        document = ReportDocument(
            report_type=report_type,
            title=report_type.label,
            generated_at=utcnow(),
            generated_by=generated_by,
            period_start=start,
            period_end=end,
            scope=scope,
        )

        builders = {
            ReportType.VULNERABILITY: self._build_vulnerability,
            ReportType.NETWORK_MONITORING: self._build_network,
            ReportType.IDS_ALERT: self._build_ids,
            ReportType.THREAT_INCIDENT: self._build_incidents,
            ReportType.MITIGATION: self._build_mitigation,
            ReportType.SYSTEM_ACTIVITY: self._build_activity,
            ReportType.EXECUTIVE_SUMMARY: self._build_executive,
            ReportType.SECURITY_ASSESSMENT: self._build_security_assessment,
        }
        builders.get(report_type, self._build_security_assessment)(
            document, start, end, limit
        )

        if not document.has_records:
            document.conclusion = (
                "No records matched the selected period and scope. This is an "
                "accurate reflection of the stored data: AETHRA-SEC reports "
                "only what its subsystems actually observed."
            )
        elif not document.conclusion:
            document.conclusion = self._default_conclusion(document)
        return document

    # ------------------------------------------------------------------
    # Individual reports
    # ------------------------------------------------------------------
    def _build_vulnerability(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """Vulnerability assessment results and derived findings."""
        scans = self._scans.search_scans(start=start, end=end, limit=min(limit, 500))
        doc.sections.append(
            ReportSection(
                title="Assessments performed",
                columns=("Scan", "Target", "Profile", "Status", "Started", "Duration", "Result"),
                rows=[
                    (
                        s.id, s.target, s.profile_label or s.profile, str(s.status),
                        format_local(s.started_at),
                        f"{s.duration_seconds:.1f}s" if s.duration_seconds else "-",
                        s.summary_line,
                    )
                    for s in scans
                ],
                note=EDUCATIONAL_NOTES["findings"],
            )
        )

        findings = self._scans.search_findings(start=start, end=end, limit=limit)
        doc.sections.append(
            ReportSection(
                title="Security findings",
                columns=("Risk", "Host", "Port", "Service", "Finding", "Reference", "Status"),
                rows=[
                    (
                        str(f.risk_level), f.ip_address,
                        f"{f.port}/{f.protocol}" if f.port else "-",
                        f.service or "-", f.title, f.reference_text, f.status_text,
                    )
                    for f in findings
                ],
                note=EDUCATIONAL_NOTES["open_ports"],
            )
        )

        by_risk = self._scans.count_findings_by_risk()
        doc.sections.append(
            ReportSection(
                title="Finding severity distribution",
                columns=("Risk level", "Open findings"),
                rows=[(level, count) for level, count in sorted(by_risk.items())],
                derived=True,
            )
        )
        doc.highlights = [
            ("Assessments in period", format_count(len(scans))),
            ("Findings recorded", format_count(len(findings))),
            ("Open findings (all time)", format_count(self._scans.count_open_findings())),
            ("Open ports (latest scans)", format_count(self._scans.count_open_ports())),
        ]

    def _build_network(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """Traffic monitoring statistics from stored aggregates and metadata."""
        aggregates = self._traffic.aggregates_between(start, end)
        total_packets = sum(a.packet_count for a in aggregates)
        total_bytes = sum(a.byte_count for a in aggregates)
        duration = max(1.0, (end - start).total_seconds())

        doc.sections.append(
            ReportSection(
                title="Traffic intervals",
                columns=("Interval start", "Interface", "Packets", "Bytes", "Packets/s", "Bytes/s"),
                rows=[
                    (
                        format_local(a.interval_start), a.interface or "-",
                        format_count(a.packet_count), format_bytes(a.byte_count),
                        f"{a.packets_per_second:.2f}", f"{a.bytes_per_second:.0f}",
                    )
                    for a in aggregates[-limit:]
                ],
                note=EDUCATIONAL_NOTES["traffic"],
                summary=(
                    f"{format_count(total_packets)} packets, "
                    f"{format_bytes(total_bytes)} over the period."
                ),
            )
        )

        protocols = self._traffic.protocol_distribution(start)
        doc.sections.append(
            ReportSection(
                title="Protocol distribution",
                columns=("Protocol", "Packets", "Share"),
                rows=[
                    (
                        p.protocol, format_count(p.packets),
                        f"{p.share_of(total_packets):.1f}%",
                    )
                    for p in protocols
                ],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Top source addresses",
                columns=("Source", "Packets", "Bytes"),
                rows=[
                    (t.address, format_count(t.packets), format_bytes(t.bytes))
                    for t in self._traffic.top_sources(start, 20)
                ],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Top destination ports",
                columns=("Port", "Protocol", "Packets"),
                rows=[
                    (p.port, p.protocol, format_count(p.packets))
                    for p in self._traffic.top_ports(start, 20)
                ],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Observed hosts",
                columns=("IP", "Hostname", "MAC", "First seen", "Last seen", "Packets"),
                rows=[
                    (
                        h.ip_address, h.hostname or "-", h.mac_address or "-",
                        format_local(h.first_seen), format_local(h.last_seen),
                        format_count(h.packet_count),
                    )
                    for h in self._hosts.search(seen_since=start, limit=min(limit, 500))
                ],
            )
        )
        doc.highlights = [
            ("Packets observed", format_count(total_packets)),
            ("Traffic volume", format_bytes(total_bytes)),
            ("Mean packet rate", format_rate(total_packets / duration)),
            ("Hosts observed", format_count(self._hosts.count_active_since(start))),
        ]

    def _build_ids(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """Snort alerts and their analyst classification."""
        alerts = self._alerts.search_alerts(start=start, end=end, limit=limit)
        doc.sections.append(
            ReportSection(
                title="IDS alerts",
                columns=(
                    "Time", "Severity", "Signature", "Message", "Protocol",
                    "Source", "Destination", "Status", "Evaluation",
                ),
                rows=[
                    (
                        format_local(a.effective_time), str(a.severity),
                        a.signature_text, a.message, a.protocol or "-",
                        f"{a.src_ip}:{a.src_port}" if a.src_port else a.src_ip or "-",
                        f"{a.dst_ip}:{a.dst_port}" if a.dst_port else a.dst_ip or "-",
                        str(a.status), str(a.evaluation),
                    )
                    for a in alerts
                ],
                note=EDUCATIONAL_NOTES["alerts"],
            )
        )
        severity = self._alerts.count_by_severity(start)
        doc.sections.append(
            ReportSection(
                title="Alert severity distribution",
                columns=("Severity", "Alerts"),
                rows=[(level, count) for level, count in sorted(severity.items())],
                derived=True,
            )
        )
        anomalies = self._alerts.search_anomalies(start=start, end=end, limit=limit)
        doc.sections.append(
            ReportSection(
                title="Traffic anomalies",
                columns=(
                    "First seen", "Severity", "Rule", "Observation",
                    "Measured", "Threshold", "Window (s)", "Occurrences",
                ),
                rows=[
                    (
                        format_local(a.first_seen), str(a.severity), a.rule_id,
                        a.observation, f"{a.observed_value:g}",
                        f"{a.threshold_value:g}", a.window_seconds, a.event_count,
                    )
                    for a in anomalies
                ],
                note=EDUCATIONAL_NOTES["anomalies"],
            )
        )

        reliability = self._alerts.reliability_counters()
        latency = self._alerts.mean_detection_latency(start)
        doc.sections.append(
            ReportSection(
                title="Alert reliability",
                columns=("Measure", "Value"),
                rows=[
                    ("Alerts stored", format_count(reliability.get("stored", 0))),
                    ("Duplicate occurrences folded", format_count(reliability.get("duplicates", 0))),
                    ("Alerts correlated into incidents", format_count(reliability.get("correlated", 0))),
                    ("Alerts still unreviewed", format_count(reliability.get("unresolved", 0))),
                    (
                        "Mean ingest latency",
                        f"{latency:.3f} s" if latency is not None else "Not measurable",
                    ),
                ],
                derived=True,
            )
        )
        doc.highlights = [
            ("Alerts in period", format_count(len(alerts))),
            ("Anomalies in period", format_count(len(anomalies))),
            ("Critical alerts", format_count(severity.get("CRITICAL", 0))),
            ("High alerts", format_count(severity.get("HIGH", 0))),
        ]

    def _build_incidents(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """Correlated incidents with their evidence provenance."""
        incidents = self._incidents.search(start=start, end=end, limit=limit)
        doc.sections.append(
            ReportSection(
                title="Threat incidents",
                columns=(
                    "Reference", "Severity", "Confidence", "Category", "Title",
                    "Evidence sources", "Status", "First seen", "Last seen",
                ),
                rows=[
                    (
                        i.reference, str(i.severity), f"{i.confidence}%",
                        i.category.label, i.title, i.source_label, str(i.status),
                        format_local(i.first_seen), format_local(i.last_seen),
                    )
                    for i in incidents
                ],
                note=EDUCATIONAL_NOTES["incidents"],
            )
        )
        doc.sections.append(
            ReportSection(
                title="Incident severity distribution",
                columns=("Severity", "Open incidents"),
                rows=[
                    (level, count)
                    for level, count in sorted(self._incidents.count_by_severity().items())
                ],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Incident categories",
                columns=("Category", "Incidents"),
                rows=[
                    (category, count)
                    for category, count in sorted(
                        self._incidents.count_by_category(start).items()
                    )
                ],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Analyst evaluation",
                columns=("Classification", "Incidents"),
                rows=[
                    (label, count)
                    for label, count in sorted(self._incidents.evaluation_counts().items())
                ],
                note=(
                    "Classifications are applied by an authorised evaluator. "
                    "AETHRA-SEC never labels a detection true or false "
                    "positive automatically."
                ),
                derived=True,
            )
        )
        doc.highlights = [
            ("Incidents in period", format_count(len(incidents))),
            ("Open incidents", format_count(self._incidents.count_open())),
            (
                "Multi-source incidents",
                format_count(sum(1 for i in incidents if i.is_multi_source)),
            ),
        ]

    def _build_mitigation(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """Mitigation guidance attached to real incidents."""
        incidents = self._incidents.search(start=start, end=end, limit=limit)
        rows: list[tuple[Any, ...]] = []
        for incident in incidents:
            if not incident.mitigation_id:
                continue
            rows.append(
                (
                    incident.reference, str(incident.severity), incident.title,
                    incident.affected_host_ip or "-", incident.affected_service or "-",
                    str(incident.status),
                )
            )
        doc.sections.append(
            ReportSection(
                title="Incidents with mitigation guidance",
                columns=(
                    "Incident", "Severity", "Threat", "Affected asset",
                    "Affected service", "Status",
                ),
                rows=rows,
                note=(
                    "AETHRA-SEC recommends only. No mitigation is applied "
                    "automatically: an authorised operator reviews the guidance "
                    "and decides what to do."
                ),
            )
        )
        findings = self._scans.search_findings(
            start=start, end=end, unresolved_only=True, limit=limit
        )
        doc.sections.append(
            ReportSection(
                title="Open findings requiring action",
                columns=("Risk", "Host", "Port", "Finding", "Recommended review"),
                rows=[
                    (
                        str(f.risk_level), f.ip_address,
                        f"{f.port}/{f.protocol}" if f.port else "-", f.title,
                        f.concern[:200],
                    )
                    for f in findings
                ],
            )
        )
        doc.highlights = [
            ("Incidents with guidance", format_count(len(rows))),
            ("Open findings", format_count(len(findings))),
        ]

    def _build_activity(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """System and operator activity from the audit trail."""
        records = self._audit.search(start=start, end=end, limit=limit)
        doc.sections.append(
            ReportSection(
                title="Audit trail",
                columns=("Time", "User", "Action", "Category", "Target", "Result", "Detail"),
                rows=[
                    (
                        format_local(r.occurred_at), r.username or "-", r.action,
                        r.category, f"{r.target_type}:{r.target_id}".strip(":"),
                        r.result, (r.detail or "")[:300],
                    )
                    for r in records
                ],
                note=(
                    "Audit records are append-only and chained with SHA-256 "
                    "hashes. Use Logs > Verify integrity to confirm the chain."
                ),
            )
        )
        doc.highlights = [
            ("Audit records in period", format_count(len(records))),
            ("Audit records (all time)", format_count(self._audit.total_count())),
        ]

    def _build_executive(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """A short summary of posture, drawn entirely from stored counts."""
        alerts = self._alerts.count_alerts_since(start)
        severity = self._alerts.count_by_severity(start)
        incidents = self._incidents.search(start=start, end=end, limit=limit)
        findings_by_risk = self._scans.count_findings_by_risk()
        aggregates = self._traffic.aggregates_between(start, end)
        total_packets = sum(a.packet_count for a in aggregates)

        doc.highlights = [
            ("Packets observed", format_count(total_packets)),
            ("Hosts observed", format_count(self._hosts.count_active_since(start))),
            ("IDS alerts", format_count(alerts)),
            ("Critical + high alerts", format_count(
                severity.get("CRITICAL", 0) + severity.get("HIGH", 0)
            )),
            ("Incidents", format_count(len(incidents))),
            ("Open incidents", format_count(self._incidents.count_open())),
            ("Open findings", format_count(self._scans.count_open_findings())),
        ]
        doc.sections.append(
            ReportSection(
                title="Security posture summary",
                columns=("Measure", "Value"),
                rows=[(label, value) for label, value in doc.highlights],
                derived=True,
            )
        )
        doc.sections.append(
            ReportSection(
                title="Most serious open incidents",
                columns=("Reference", "Severity", "Title", "Evidence", "Status"),
                rows=[
                    (i.reference, str(i.severity), i.title, i.source_label, str(i.status))
                    for i in sorted(
                        (i for i in incidents if i.status.is_open),
                        key=lambda i: i.severity.rank,
                        reverse=True,
                    )[:20]
                ],
            )
        )
        doc.sections.append(
            ReportSection(
                title="Findings by risk level",
                columns=("Risk level", "Open findings"),
                rows=[(level, count) for level, count in sorted(findings_by_risk.items())],
                note=EDUCATIONAL_NOTES["open_ports"],
                derived=True,
            )
        )
        doc.observations = self._observations(
            total_packets, alerts, len(incidents), findings_by_risk
        )

    def _build_security_assessment(
        self, doc: ReportDocument, start: datetime, end: datetime, limit: int
    ) -> None:
        """The combined report: assessment, monitoring, detection and response."""
        self._build_executive(doc, start, end, min(limit, 200))
        doc.sections.append(
            ReportSection(
                title="Hosts assessed",
                columns=("IP", "Hostname", "OS", "Open ports", "Risk", "Last seen"),
                rows=[
                    (
                        h.ip_address, h.hostname or "-", h.os_text,
                        h.open_port_count, str(h.risk_level),
                        format_local(h.last_seen),
                    )
                    for h in self._hosts.search(limit=min(limit, 500))
                ],
            )
        )
        findings = self._scans.search_findings(start=start, end=end, limit=min(limit, 500))
        doc.sections.append(
            ReportSection(
                title="Findings detail",
                columns=("Risk", "Host", "Port", "Finding", "Why it matters", "Reference"),
                rows=[
                    (
                        str(f.risk_level), f.ip_address,
                        f"{f.port}/{f.protocol}" if f.port else "-", f.title,
                        (f.concern or "")[:250], f.reference_text,
                    )
                    for f in findings
                ],
                note=EDUCATIONAL_NOTES["findings"],
            )
        )
        alerts = self._alerts.search_alerts(start=start, end=end, limit=min(limit, 500))
        doc.sections.append(
            ReportSection(
                title="IDS alerts",
                columns=("Time", "Severity", "Signature", "Message", "Source", "Destination"),
                rows=[
                    (
                        format_local(a.effective_time), str(a.severity),
                        a.signature_text, a.message, a.src_ip or "-", a.dst_ip or "-",
                    )
                    for a in alerts
                ],
                note=EDUCATIONAL_NOTES["alerts"],
            )
        )
        incidents = self._incidents.search(start=start, end=end, limit=min(limit, 500))
        doc.sections.append(
            ReportSection(
                title="Incidents and evidence provenance",
                columns=("Reference", "Severity", "Title", "Evidence sources", "Status"),
                rows=[
                    (i.reference, str(i.severity), i.title, i.source_label, str(i.status))
                    for i in incidents
                ],
                note=EDUCATIONAL_NOTES["incidents"],
            )
        )

    # ------------------------------------------------------------------
    # Narrative
    # ------------------------------------------------------------------
    @staticmethod
    def _observations(
        packets: int, alerts: int, incidents: int, findings_by_risk: dict[str, int]
    ) -> list[str]:
        """Factual observations derived from the counts above."""
        notes: list[str] = []
        if packets == 0:
            notes.append(
                "No packets were captured in this period. Either capture was "
                "not running, or the monitoring interface saw no traffic."
            )
        else:
            notes.append(f"{format_count(packets)} packets were observed and analysed.")

        if alerts == 0:
            notes.append(
                "No Snort alerts were received in this period. Confirm on the "
                "System Health screen that the alert transport is connected - "
                "an absence of alerts is only meaningful when the sensor is "
                "known to be running."
            )
        else:
            notes.append(f"{format_count(alerts)} IDS alerts were received and stored.")

        critical = findings_by_risk.get("CRITICAL", 0) + findings_by_risk.get("HIGH", 0)
        if critical:
            notes.append(
                f"{format_count(critical)} open finding(s) are rated HIGH or "
                "CRITICAL and should be reviewed first."
            )
        elif findings_by_risk:
            notes.append(
                "No open findings are rated HIGH or CRITICAL in the current "
                "assessment data."
            )

        if incidents:
            notes.append(
                f"{format_count(incidents)} incident(s) were correlated from "
                "the evidence recorded in this period."
            )
        return notes

    @staticmethod
    def _default_conclusion(document: ReportDocument) -> str:
        """A conclusion that describes only what the report actually contains."""
        return (
            f"This report covers {format_count(document.total_records)} record(s) "
            f"stored between {format_local(document.period_start)} and "
            f"{format_local(document.period_end)}. Every figure is derived from "
            "records produced by Nmap, PyShark/TShark or Snort, or from "
            "deterministic rules applied to those records. Sections showing no "
            "rows had no matching data - they are not omissions."
        )


def sections_to_rows(sections: Sequence[ReportSection]) -> list[tuple[Any, ...]]:
    """Flatten sections into one row list for a single-sheet CSV export."""
    rows: list[tuple[Any, ...]] = []
    for section in sections:
        rows.append((f"### {section.title}",))
        rows.append(section.columns)
        if section.has_rows:
            rows.extend(section.rows)
        else:
            rows.append((NO_RECORDS_TEXT,))
        rows.append(())
    return rows
