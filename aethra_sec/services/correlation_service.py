"""Threat correlation engine (§25-§28, §77, §78).

This is the component that makes AETHRA-SEC more than three tools in one
window. It takes the evidence each subsystem produced independently -

* Snort alerts,
* deterministic traffic anomalies from PyShark observations,
* Nmap assessment findings -

and groups related evidence into a single **incident**, scores it with the
transparent risk engine, and attaches mitigation guidance.

Two rules are absolute:

* **No fabricated correlation** (§78). An incident lists exactly which
  subsystems contributed. One source means the incident says so - it never
  implies Nmap confirmed something Nmap did not observe.
* **No alert flooding** (§26). Evidence sharing a correlation key inside the
  configured window is attached to the existing incident rather than creating
  a new one.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

from aethra_sec.analytics.risk_engine import RiskEngine, ThreatEvidence
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import (
    EventType,
    IncidentPayload,
    MitigationPayload,
    NotificationPayload,
)
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    IncidentStatus,
    NotificationLevel,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.incident import Incident, IncidentEvent
from aethra_sec.models.scan import ScanFinding
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.mitigation_service import MitigationService
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import service_name_for_port
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.correlation")

#: Keyword rules mapping Snort signature text to a threat category. Ordered:
#: the first matching group wins, so specific patterns precede general ones.
_CATEGORY_KEYWORDS: tuple[tuple[ThreatCategory, tuple[str, ...]], ...] = (
    (
        ThreatCategory.MALWARE_INDICATOR,
        ("trojan", "malware", "botnet", "command and control", "c2 ", "cnc",
         "ransomware", "backdoor", "spyware", "worm", "exploit kit"),
    ),
    (
        ThreatCategory.BRUTE_FORCE,
        ("brute", "login attempt", "failed login", "password guess",
         "authentication failure", "excessive login", "credential"),
    ),
    (
        ThreatCategory.SUSPICIOUS_PAYLOAD,
        ("shellcode", "buffer overflow", "sql injection", "sqli",
         "cross site scripting", "xss", "directory traversal", "file include",
         "command injection", "obfuscat", "suspicious payload", "attempted-admin",
         "attempted-user", "web-application-attack"),
    ),
    (
        ThreatCategory.DENIAL_OF_SERVICE,
        ("denial of service", "dos ", "ddos", "flood", "resource exhaustion",
         "attempted-dos"),
    ),
    (
        ThreatCategory.PORT_SCAN,
        ("portscan", "port scan", "port sweep", "nmap", "scan detected",
         "network-scan", "syn scan"),
    ),
    (
        ThreatCategory.HOST_SWEEP,
        ("host sweep", "icmp sweep", "ping sweep", "network sweep"),
    ),
    (
        ThreatCategory.RECONNAISSANCE,
        ("scan", "recon", "probe", "enumeration", "information leak",
         "attempted-recon", "banner"),
    ),
    (
        ThreatCategory.POLICY_VIOLATION,
        ("policy", "policy-violation", "not-suspicious", "unusual client"),
    ),
)


@dataclass
class CorrelationStatistics:
    """Real counters for the System Health screen."""

    runs: int = 0
    events_processed: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    alerts_attached: int = 0
    anomalies_attached: int = 0
    findings_linked: int = 0
    errors: int = 0
    last_run_at: datetime | None = None


def categorise_alert(alert: SnortAlert) -> ThreatCategory:
    """Map a Snort alert to a threat category from its own text.

    Uses the signature message and classification the sensor supplied. When
    nothing matches, the category is ``UNCLASSIFIED`` - which the mitigation
    knowledge base has an entry for, so the analyst still gets guidance.
    """
    haystack = f"{alert.message} {alert.classification}".lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return category
    return ThreatCategory.UNCLASSIFIED


class CorrelationService:
    """Groups multi-source evidence into scored, explainable incidents."""

    def __init__(
        self,
        incidents: IncidentRepository,
        alerts: AlertRepository,
        scans: ScanRepository,
        hosts: HostRepository,
        mitigation: MitigationService,
        settings: SettingsService,
        event_bus: EventBus,
        audit: AuditService,
        access: AccessControl,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        """Wire the engine to its collaborators."""
        self._incidents = incidents
        self._alerts = alerts
        self._scans = scans
        self._hosts = hosts
        self._mitigation = mitigation
        self._settings = settings
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._risk = risk_engine or RiskEngine()
        self._lock = threading.RLock()
        self.statistics = CorrelationStatistics()

    # ------------------------------------------------------------------
    # Correlation cycle
    # ------------------------------------------------------------------
    def correlate_recent(self) -> int:
        """Correlate evidence that has not yet been attached to an incident.

        Runs on the background scheduler. Returns the number of evidence events
        processed. Never raises: correlation failing must not stop monitoring.
        """
        if not self._settings.get_bool("correlation.enabled", True):
            return 0

        with self._lock:
            self.statistics.runs += 1
            self.statistics.last_run_at = utcnow()

        window = max(10, self._settings.get_int("correlation.window_seconds", 300))
        # Look back over several windows so evidence that arrived while the
        # database was briefly unavailable is still picked up.
        since = utcnow() - timedelta(seconds=window * 4)
        processed = 0

        try:
            for alert in self._alerts.uncorrelated_alerts(since, limit=500):
                if self._correlate_alert(alert, window):
                    processed += 1
            for anomaly in self._alerts.uncorrelated_anomalies(since, limit=500):
                if self._correlate_anomaly(anomaly, window):
                    processed += 1
        except Exception:  # noqa: BLE001 - correlation must never break the app
            with self._lock:
                self.statistics.errors += 1
            LOGGER.exception("Correlation cycle failed.")

        with self._lock:
            self.statistics.events_processed += processed
        return processed

    def _correlate_alert(self, alert: SnortAlert, window: int) -> bool:
        """Attach one Snort alert to an incident, creating one if needed."""
        if alert.id is None:
            return False
        category = categorise_alert(alert)
        service = self._service_for(alert.dst_ip, alert.dst_port, alert.protocol)
        key = self._correlation_key(category, alert.src_ip, alert.dst_ip, alert.dst_port)

        incident = self._find_or_create(
            key=key,
            category=category,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            service=service,
            occurred_at=alert.effective_time or utcnow(),
            title=self._title_for(category, alert.src_ip, alert.dst_ip, alert.message),
            window=window,
        )
        if incident is None or incident.id is None:
            return False

        self._incidents.add_event(
            IncidentEvent(
                incident_id=incident.id,
                source=EvidenceSource.SNORT,
                event_type="snort_alert",
                reference_table="snort_alerts",
                reference_id=alert.id,
                occurred_at=alert.effective_time,
                summary=f"{alert.signature_text} {alert.message}"[:512],
                detail=(
                    f"Snort priority {alert.priority if alert.priority is not None else 'not supplied'}"
                    f"; classification: {alert.classification or 'not supplied'}"
                    f"; transport: {alert.transport or 'unknown'}"
                ),
            )
        )
        self._alerts.set_alert_incident(alert.id, incident.id)
        with self._lock:
            self.statistics.alerts_attached += 1
        self._refresh(incident)
        return True

    def _correlate_anomaly(self, anomaly: TrafficAnomaly, window: int) -> bool:
        """Attach one traffic anomaly to an incident, creating one if needed."""
        if anomaly.id is None:
            return False
        service = self._service_for(anomaly.dst_ip, anomaly.dst_port, anomaly.protocol)
        key = self._correlation_key(
            anomaly.category, anomaly.src_ip, anomaly.dst_ip, anomaly.dst_port
        )

        incident = self._find_or_create(
            key=key,
            category=anomaly.category,
            src_ip=anomaly.src_ip,
            dst_ip=anomaly.dst_ip,
            dst_port=anomaly.dst_port,
            protocol=anomaly.protocol,
            service=service,
            occurred_at=anomaly.first_seen or utcnow(),
            title=self._title_for(
                anomaly.category, anomaly.src_ip, anomaly.dst_ip, anomaly.title
            ),
            window=window,
        )
        if incident is None or incident.id is None:
            return False

        self._incidents.add_event(
            IncidentEvent(
                incident_id=incident.id,
                source=EvidenceSource.PYSHARK,
                event_type="traffic_anomaly",
                reference_table="traffic_anomalies",
                reference_id=anomaly.id,
                occurred_at=anomaly.first_seen,
                summary=anomaly.observation[:512] or anomaly.title,
                detail=(
                    f"Rule {anomaly.rule_id}; measured {anomaly.observed_value:g} "
                    f"against threshold {anomaly.threshold_value:g} over "
                    f"{anomaly.window_seconds}s; "
                    + "; ".join(anomaly.evidence_lines()[:8])
                ),
            )
        )
        self._alerts.set_anomaly_incident(anomaly.id, incident.id)
        with self._lock:
            self.statistics.anomalies_attached += 1
        self._refresh(incident)
        return True

    # ------------------------------------------------------------------
    # Incident lifecycle
    # ------------------------------------------------------------------
    @staticmethod
    def _correlation_key(
        category: ThreatCategory, src_ip: str, dst_ip: str, dst_port: int | None
    ) -> str:
        """Build the key that decides which evidence belongs together (§26).

        Rate-based categories group by ``source -> destination`` because the
        port varies within one flood; scan and sweep categories group by source
        and destination host, since the varying ports *are* the pattern.
        """
        if category in (
            ThreatCategory.PORT_SCAN,
            ThreatCategory.HOST_SWEEP,
            ThreatCategory.RECONNAISSANCE,
        ):
            return f"{category}|{src_ip}|{dst_ip}"
        if category in (
            ThreatCategory.TCP_SYN_FLOOD,
            ThreatCategory.UDP_FLOOD,
            ThreatCategory.ICMP_FLOOD,
            ThreatCategory.HTTP_FLOOD,
            ThreatCategory.DENIAL_OF_SERVICE,
        ):
            return f"{category}|{src_ip}|{dst_ip}"
        return f"{category}|{src_ip}|{dst_ip}|{dst_port or ''}"

    @staticmethod
    def _title_for(
        category: ThreatCategory, src_ip: str, dst_ip: str, detail: str
    ) -> str:
        """Compose an incident title in observation-not-verdict language."""
        titles = {
            ThreatCategory.PORT_SCAN: "Port scanning behaviour",
            ThreatCategory.HOST_SWEEP: "Network sweep behaviour",
            ThreatCategory.BRUTE_FORCE: "Potential brute-force activity",
            ThreatCategory.TCP_SYN_FLOOD: "Potential TCP SYN flood",
            ThreatCategory.UDP_FLOOD: "UDP flood indicator",
            ThreatCategory.ICMP_FLOOD: "Excessive ICMP traffic",
            ThreatCategory.HTTP_FLOOD: "Abnormal HTTP request volume",
            ThreatCategory.SUSPICIOUS_PAYLOAD: "Suspicious payload detected",
            ThreatCategory.MALWARE_INDICATOR: "Malware-related indicator",
            ThreatCategory.DENIAL_OF_SERVICE: "Denial of service indicators",
            ThreatCategory.SERVICE_EXPOSURE: "Exposed network service",
            ThreatCategory.RECONNAISSANCE: "Reconnaissance activity",
            ThreatCategory.POLICY_VIOLATION: "Policy violation",
            ThreatCategory.UNCLASSIFIED: "Unclassified security event",
        }
        base = titles.get(category, "Security event")
        if src_ip and dst_ip:
            return f"{base}: {src_ip} -> {dst_ip}"
        if src_ip:
            return f"{base} from {src_ip}"
        if dst_ip:
            return f"{base} against {dst_ip}"
        return f"{base}: {detail[:60]}" if detail else base

    def _find_or_create(
        self,
        *,
        key: str,
        category: ThreatCategory,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        protocol: str,
        service: str,
        occurred_at: datetime,
        title: str,
        window: int,
    ) -> Incident | None:
        """Return the incident this evidence belongs to, creating it if needed."""
        include_resolved = self._settings.get_bool("correlation.reopen_resolved", False)
        existing = self._incidents.find_open_by_correlation_key(
            key, utcnow() - timedelta(seconds=window), include_resolved
        )
        if existing is not None:
            with self._lock:
                self.statistics.incidents_updated += 1
            return existing

        affected_ip = dst_ip or src_ip
        host_id = self._hosts.find_id_by_ip(affected_ip) if affected_ip else None
        incident = Incident(
            reference=self._incidents.next_reference(),
            title=title[:190],
            description="",
            category=category,
            severity=Severity.MEDIUM,
            confidence=0,
            status=IncidentStatus.NEW,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            affected_host_id=host_id,
            affected_host_ip=affected_ip,
            affected_service=service,
            correlation_key=key,
            first_seen=occurred_at,
            last_seen=occurred_at,
            created_at=utcnow(),
            evaluation=EvaluationLabel.UNCLASSIFIED,
        )
        try:
            incident.id = self._incidents.create(incident)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not create an incident for key %s", key)
            return None

        with self._lock:
            self.statistics.incidents_created += 1
        LOGGER.info("Incident %s created (%s).", incident.reference, key)
        return incident

    def _refresh(self, incident: Incident) -> None:
        """Recompute an incident from all of its attached evidence."""
        if incident.id is None:
            return
        try:
            events = self._incidents.events_for(incident.id)
            alerts = self._alerts.alerts_for_incident(incident.id)
            anomalies = self._alerts.anomalies_for_incident(incident.id)
            findings = self._related_findings(incident)

            sources: list[EvidenceSource] = []
            if alerts:
                sources.append(EvidenceSource.SNORT)
            if anomalies:
                sources.append(EvidenceSource.PYSHARK)
            if findings:
                sources.append(EvidenceSource.NMAP)
            if not sources:
                sources.append(EvidenceSource.CORRELATION)

            trusted = self._hosts.trusted_addresses()
            priorities = [a.priority for a in alerts if a.priority is not None]
            evidence = ThreatEvidence(
                category=incident.category,
                snort_priority=min(priorities) if priorities else None,
                snort_alert_count=len(alerts),
                anomaly_count=len(anomalies),
                finding_count=len(findings),
                distinct_sources=len({s for s in sources if s is not EvidenceSource.CORRELATION})
                or 1,
                event_count=max(len(events), len(alerts) + len(anomalies)),
                affected_service=incident.affected_service,
                target_is_trusted=incident.affected_host_ip in trusted,
                source_is_trusted=incident.src_ip in trusted,
                exposure_confirmed=bool(findings),
                repeat_observations=sum(a.event_count for a in anomalies)
                + sum(a.duplicate_count for a in alerts),
            )
            assessment = self._risk.score_threat(evidence)

            first_seen = min(
                [e.occurred_at for e in events if e.occurred_at]
                + ([incident.first_seen] if incident.first_seen else [])
                or [utcnow()]
            )
            last_seen = max(
                [e.occurred_at for e in events if e.occurred_at]
                + ([incident.last_seen] if incident.last_seen else [])
                or [utcnow()]
            )

            for finding in findings:
                self._link_finding(incident.id, finding)

            description = self._describe(
                incident, alerts, anomalies, findings, sources, assessment
            )
            advice = self._mitigation.advice_for_incident(
                incident,
                self._evidence_lines(alerts, anomalies, findings),
            )
            mitigation_id = advice.recommendation.id if advice else None

            self._incidents.update_correlation_state(
                incident.id,
                severity=assessment.severity,
                confidence=assessment.confidence,
                risk_score=assessment.score,
                risk_rationale="\n".join(assessment.explanation_lines()),
                evidence_sources=tuple(dict.fromkeys(sources)),
                event_count=len(events),
                snort_alert_count=len(alerts),
                anomaly_count=len(anomalies),
                finding_count=len(findings),
                last_seen=last_seen,
                description=description,
                mitigation_id=mitigation_id,
            )

            refreshed = self._incidents.get(incident.id)
            if refreshed is None:
                return
            refreshed.first_seen = first_seen

            is_new = len(events) <= 1
            self._bus.publish(
                EventType.INCIDENT_CREATED if is_new else EventType.INCIDENT_UPDATED,
                IncidentPayload(incident=refreshed, is_new=is_new),
            )
            if is_new:
                self._audit.record(
                    AuditAction.INCIDENT_CREATED,
                    category=AuditCategory.DETECTION,
                    target_type="incident",
                    target_id=refreshed.reference,
                    detail=(
                        f"{refreshed.title} | severity {refreshed.severity} "
                        f"(score {assessment.score}, confidence "
                        f"{assessment.confidence}%) | evidence: "
                        f"{refreshed.source_label}"
                    ),
                )
                self._notify(refreshed)
            if advice and mitigation_id:
                self._bus.publish(
                    EventType.MITIGATION_GENERATED,
                    MitigationPayload(
                        incident_id=incident.id,
                        recommendation_id=mitigation_id,
                        title=advice.recommendation.threat_name,
                        severity=assessment.severity,
                    ),
                )
                if is_new:
                    self._audit.record(
                        AuditAction.MITIGATION_GENERATED,
                        category=AuditCategory.MITIGATION,
                        target_type="incident",
                        target_id=refreshed.reference,
                        detail=(
                            f"Recommendation '{advice.recommendation.code}' "
                            f"attached to {refreshed.reference}."
                        ),
                    )
        except Exception:  # noqa: BLE001
            with self._lock:
                self.statistics.errors += 1
            LOGGER.exception("Could not refresh incident %s", incident.id)

    def _related_findings(self, incident: Incident) -> list[ScanFinding]:
        """Nmap findings that genuinely relate to this incident (§77).

        Only findings for the affected host are considered, and when the
        incident names a port, only findings for that port. This is what lets
        an incident say "Nmap confirmed the targeted service is exposed"
        truthfully - and stay silent when it did not.
        """
        if not incident.affected_host_id:
            return []
        try:
            findings = self._scans.findings_for_host(incident.affected_host_id, limit=100)
        except Exception:  # noqa: BLE001
            return []
        open_findings = [f for f in findings if f.resolved_at is None]
        if incident.dst_port:
            matched = [f for f in open_findings if f.port == incident.dst_port]
            if matched:
                return matched
        if incident.affected_service:
            matched = [
                f
                for f in open_findings
                if f.service.lower() == incident.affected_service.lower()
            ]
            if matched:
                return matched
        # For scan and sweep categories the whole exposed surface is relevant.
        if incident.category in (
            ThreatCategory.PORT_SCAN,
            ThreatCategory.HOST_SWEEP,
            ThreatCategory.RECONNAISSANCE,
        ):
            return open_findings[:10]
        return []

    def _link_finding(self, incident_id: int, finding: ScanFinding) -> None:
        """Attach an Nmap finding to an incident as evidence."""
        if finding.id is None:
            return
        try:
            self._incidents.add_event(
                IncidentEvent(
                    incident_id=incident_id,
                    source=EvidenceSource.NMAP,
                    event_type="scan_finding",
                    reference_table="scan_findings",
                    reference_id=finding.id,
                    occurred_at=finding.created_at,
                    summary=f"[{finding.risk_level}] {finding.title}"[:512],
                    detail=f"{finding.observation}\n{finding.risk_rationale}",
                )
            )
            with self._lock:
                self.statistics.findings_linked += 1
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not link finding %s", finding.id, exc_info=True)

    @staticmethod
    def _evidence_lines(
        alerts: Sequence[SnortAlert],
        anomalies: Sequence[TrafficAnomaly],
        findings: Sequence[ScanFinding],
    ) -> tuple[str, ...]:
        """Render the real evidence behind an incident as readable lines."""
        lines: list[str] = []
        for alert in alerts[:10]:
            lines.append(
                f"Snort {alert.signature_text} '{alert.message}' "
                f"({alert.src_ip} -> {alert.dst_ip}"
                + (f":{alert.dst_port}" if alert.dst_port else "")
                + f", priority {alert.priority if alert.priority is not None else 'n/a'}"
                + (f", seen {alert.duplicate_count}x" if alert.duplicate_count > 1 else "")
                + ")"
            )
        for anomaly in anomalies[:10]:
            lines.append(
                f"Traffic rule {anomaly.rule_id}: {anomaly.observation}"
            )
        for finding in findings[:10]:
            lines.append(
                f"Nmap finding [{finding.risk_level}] {finding.title} - "
                f"{finding.observation}"
            )
        return tuple(lines)

    def _describe(
        self,
        incident: Incident,
        alerts: Sequence[SnortAlert],
        anomalies: Sequence[TrafficAnomaly],
        findings: Sequence[ScanFinding],
        sources: Sequence[EvidenceSource],
        assessment: Any,
    ) -> str:
        """Write the incident narrative, naming its evidence honestly (§78)."""
        distinct = [s for s in dict.fromkeys(sources) if s is not EvidenceSource.CORRELATION]
        if not distinct:
            provenance = "Evidence: correlation engine only."
        elif len(distinct) == 1:
            provenance = f"Evidence: {distinct[0].label} only."
        else:
            provenance = "Evidence: " + " + ".join(s.label for s in distinct) + "."

        parts = [
            f"{incident.title}.",
            provenance,
            "",
            "WHAT WAS OBSERVED:",
        ]
        for line in self._evidence_lines(alerts, anomalies, findings)[:8]:
            parts.append(f"  - {line}")
        if not alerts and not anomalies and not findings:
            parts.append("  - No supporting evidence records remain.")

        parts.extend(
            [
                "",
                "HOW THE SEVERITY WAS CALCULATED:",
                *(f"  {line}" for line in assessment.explanation_lines()),
                "",
                (
                    "NOTE: This incident is built from the records listed above. "
                    "Where a subsystem is not named, it did not contribute "
                    "evidence."
                ),
            ]
        )
        return "\n".join(parts)

    def _service_for(self, ip_address: str, port: int | None, protocol: str) -> str:
        """Identify the affected service, preferring what Nmap actually saw."""
        if not port:
            return ""
        if ip_address:
            try:
                host_id = self._hosts.find_id_by_ip(ip_address)
                if host_id:
                    for open_port in self._scans.open_ports_for_host(host_id):
                        if open_port.port == port:
                            return open_port.service
            except Exception:  # noqa: BLE001
                LOGGER.debug("Service lookup failed.", exc_info=True)
        return service_name_for_port(port, protocol or "tcp")

    def _notify(self, incident: Incident) -> None:
        """Raise a notification for a genuinely new incident (§52)."""
        if not self._settings.get_bool("notifications.enabled", True):
            return
        minimum = Severity.parse(
            self._settings.get_str("notifications.min_severity", "MEDIUM"),
            Severity.MEDIUM,
        )
        if not incident.severity.at_least(minimum):
            return
        level = (
            NotificationLevel.CRITICAL
            if incident.severity is Severity.CRITICAL
            else NotificationLevel.WARNING
            if incident.severity is Severity.HIGH
            else NotificationLevel.INFO
        )
        self._bus.publish(
            EventType.NOTIFICATION_RAISED,
            NotificationPayload(
                title=f"{incident.severity} incident {incident.reference}",
                message=f"{incident.title} ({incident.source_label})",
                level=level,
                category="incident",
                reference_type="incident",
                reference_id=incident.id,
            ),
        )

    # ------------------------------------------------------------------
    # Analyst operations (permission-checked)
    # ------------------------------------------------------------------
    def search(self, session: Session, **filters: Any) -> list[Incident]:
        """Search incidents."""
        self._access.require(session, Permission.INCIDENT_VIEW)
        return self._incidents.search(**filters)

    def open_incident_count(self, session: Session) -> int:
        """Open incidents nobody has read yet (the sidebar counter).

        Reading an incident clears it from this count, so the badge tracks what
        is still unseen rather than everything that happens to be open.
        """
        self._access.require(session, Permission.INCIDENT_VIEW)
        return self._incidents.count_unread()

    def mark_viewed(self, session: Session, incident_id: int) -> bool:
        """Record that an analyst has opened this incident."""
        self._access.require(session, Permission.INCIDENT_VIEW, target=str(incident_id))
        return self._incidents.mark_viewed(incident_id, session.user_id)

    def mark_all_viewed(self, session: Session) -> int:
        """Mark every unread incident as read (the sidebar's "mark all read")."""
        self._access.require(session, Permission.INCIDENT_VIEW)
        return self._incidents.mark_all_viewed(session.user_id)

    def get_investigation(self, session: Session, incident_id: int) -> Incident | None:
        """Fetch one incident with all of its evidence and notes (§44)."""
        self._access.require(session, Permission.INCIDENT_VIEW, target=str(incident_id))
        return self._incidents.get_with_evidence(incident_id)

    def evidence_bundle(self, session: Session, incident_id: int) -> dict[str, Any]:
        """Assemble everything the investigation screen renders (§44)."""
        self._access.require(session, Permission.INCIDENT_VIEW, target=str(incident_id))
        incident = self._incidents.get_with_evidence(incident_id)
        if incident is None:
            return {}
        # Opening the investigation view is what "reading" an incident means,
        # so this is where the unread counter is cleared.
        if self._incidents.mark_viewed(incident_id, session.user_id):
            incident.viewed_at = utcnow()
            incident.viewed_by = session.user_id
        alerts = self._alerts.alerts_for_incident(incident_id)
        anomalies = self._alerts.anomalies_for_incident(incident_id)
        findings = (
            self._scans.findings_for_host(incident.affected_host_id)
            if incident.affected_host_id
            else []
        )
        advice = self._mitigation.advice_for_incident(
            incident, self._evidence_lines(alerts, anomalies, findings)
        )
        host = (
            self._hosts.get(incident.affected_host_id)
            if incident.affected_host_id
            else None
        )
        return {
            "incident": incident,
            "alerts": alerts,
            "anomalies": anomalies,
            "findings": findings,
            "advice": advice,
            "host": host,
            "devices": self._devices(incident, alerts, anomalies, findings),
            "timeline": self._timeline(incident, alerts, anomalies, findings),
        }

    def _devices(
        self,
        incident: Incident,
        alerts: Sequence[SnortAlert],
        anomalies: Sequence[TrafficAnomaly],
        findings: Sequence[ScanFinding],
    ) -> list[dict[str, Any]]:
        """Every device this incident's own evidence names, with its role.

        An incident records a single ``affected_host_id``, but its evidence
        routinely spans more than one device: a scan sweeping several targets,
        one source reaching several hosts, several sources reaching one. The
        addresses are read back out of the alerts, anomalies and findings that
        are already attached to the incident, then matched against the host
        inventory so a known device shows its hostname, MAC and OS. Nothing is
        inferred: an address the inventory has never seen is listed as itself.
        """
        roles: dict[str, set[str]] = {}

        def note(address: str, role: str) -> None:
            candidate = str(address or "").strip()
            if candidate:
                roles.setdefault(candidate, set()).add(role)

        note(incident.src_ip, "source")
        note(incident.dst_ip, "target")
        note(incident.affected_host_ip, "target")
        for alert in alerts:
            note(alert.src_ip, "source")
            note(alert.dst_ip, "target")
        for anomaly in anomalies:
            note(anomaly.src_ip, "source")
            note(anomaly.dst_ip, "target")
        for finding in findings:
            note(finding.ip_address, "target")

        devices: list[dict[str, Any]] = []
        for address, kinds in roles.items():
            host = self._hosts.get_by_ip(address)
            devices.append(
                {
                    "ip": address,
                    "role": " and ".join(sorted(kinds)),
                    "is_source": "source" in kinds,
                    "hostname": host.hostname if host else "",
                    "mac": host.mac_address if host else "",
                    "os": host.os_text if host else "",
                    "status": str(host.status) if host else "",
                    "risk": str(host.risk_level) if host else "",
                    "host_id": host.id if host else None,
                    "is_trusted": bool(host and host.is_trusted),
                    "known": host is not None,
                }
            )
        # Sources first - the attacking address is what an analyst looks for.
        devices.sort(key=lambda d: (not d["is_source"], d["ip"]))
        return devices

    @staticmethod
    def _timeline(
        incident: Incident,
        alerts: Sequence[SnortAlert],
        anomalies: Sequence[TrafficAnomaly],
        findings: Sequence[ScanFinding],
    ) -> list[dict[str, Any]]:
        """Build a chronological evidence timeline from real timestamps."""
        entries: list[dict[str, Any]] = []
        for alert in alerts:
            entries.append(
                {
                    "at": alert.effective_time,
                    "source": EvidenceSource.SNORT.label,
                    "summary": f"{alert.signature_text} {alert.message}",
                }
            )
        for anomaly in anomalies:
            entries.append(
                {
                    "at": anomaly.first_seen,
                    "source": EvidenceSource.PYSHARK.label,
                    "summary": anomaly.observation or anomaly.title,
                }
            )
        for finding in findings:
            entries.append(
                {
                    "at": finding.created_at,
                    "source": EvidenceSource.NMAP.label,
                    "summary": f"[{finding.risk_level}] {finding.title}",
                }
            )
        if incident.created_at:
            entries.append(
                {
                    "at": incident.created_at,
                    "source": EvidenceSource.CORRELATION.label,
                    "summary": f"Incident {incident.reference} created by correlation.",
                }
            )
        return sorted(entries, key=lambda e: (e["at"] is None, e["at"]))

    def set_status(
        self, session: Session, incident_id: int, status: IncidentStatus
    ) -> None:
        """Change incident status (§94)."""
        live = self._access.require(
            session, Permission.INCIDENT_MANAGE, target=str(incident_id)
        )
        self._incidents.set_status(incident_id, status, live.user_id)
        self._audit.record(
            AuditAction.INCIDENT_UPDATED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="incident",
            target_id=incident_id,
            detail=f"Incident status changed to {status}.",
        )

    def assign(self, session: Session, incident_id: int, user_id: int | None) -> None:
        """Assign an incident owner."""
        live = self._access.require(
            session, Permission.INCIDENT_MANAGE, target=str(incident_id)
        )
        self._incidents.assign(incident_id, user_id)
        self._audit.record(
            AuditAction.INCIDENT_UPDATED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="incident",
            target_id=incident_id,
            detail=f"Incident assigned to user id {user_id}.",
        )

    def add_note(self, session: Session, incident_id: int, note: str) -> int:
        """Append an investigation note."""
        live = self._access.require(
            session, Permission.INCIDENT_MANAGE, target=str(incident_id)
        )
        text = (note or "").strip()
        if not text:
            return 0
        note_id = self._incidents.add_note(incident_id, live.user_id, text)
        self._audit.record(
            AuditAction.INCIDENT_NOTE_ADDED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="incident",
            target_id=incident_id,
            detail=f"Investigation note added ({len(text)} characters).",
        )
        return note_id

    def classify(
        self, session: Session, incident_id: int, evaluation: EvaluationLabel
    ) -> None:
        """Record an evaluator's classification of the incident (§82)."""
        live = self._access.require(
            session, Permission.EVALUATION_CLASSIFY, target=str(incident_id)
        )
        self._incidents.set_evaluation(incident_id, evaluation, live.user_id)
        self._audit.record(
            AuditAction.EVALUATION_RECORDED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="incident",
            target_id=incident_id,
            detail=f"Incident classified as {evaluation}.",
        )
