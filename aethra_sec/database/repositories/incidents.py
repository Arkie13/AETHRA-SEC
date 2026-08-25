"""Correlated incident persistence (§27, §44, §94)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_dt,
    as_float,
    as_int,
    as_text,
    limit_clause,
    order_clause,
)
from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    IncidentStatus,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.incident import Incident, IncidentEvent, IncidentNote
from aethra_sec.utils.timeutil import to_db, utcnow

_FILTERABLE = {
    "status", "severity", "category", "src_ip", "dst_ip", "affected_host_id",
    "assigned_user_id", "created_at", "last_seen", "first_seen", "title",
    "correlation_key", "evaluation", "reference", "affected_service",
    "protocol", "dst_port",
}
_SORTABLE = {
    "created_at", "last_seen", "first_seen", "severity", "status", "id",
    "risk_score",
}
_SELECT = (
    "SELECT i.id, i.reference, i.title, i.description, i.category, i.severity, "
    "i.confidence, i.status, i.src_ip, i.dst_ip, i.dst_port, i.protocol, "
    "i.affected_host_id, i.affected_host_ip, i.affected_service, "
    "i.correlation_key, i.evidence_sources, i.event_count, "
    "i.snort_alert_count, i.anomaly_count, i.finding_count, i.risk_score, "
    "i.risk_rationale, i.detection_latency_seconds, i.first_seen, i.last_seen, "
    "i.created_at, i.updated_at, i.resolved_at, i.assigned_user_id, "
    "i.mitigation_id, i.evaluation, i.evaluated_by, i.evaluated_at, "
    "i.viewed_at, i.viewed_by, "
    "u.username AS assigned_username FROM incidents i "
    "LEFT JOIN users u ON u.id = i.assigned_user_id"
)

#: Statuses that still need an analyst's attention. Shared by the open and the
#: unread counters so they can never drift apart.
_OPEN_STATUSES = "('NEW','INVESTIGATING','ACKNOWLEDGED')"


class IncidentRepository(Repository):
    """Persists incidents, their evidence links and analyst notes."""

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _map(row: dict[str, Any]) -> Incident:
        """Map a joined row to :class:`Incident`."""
        sources = tuple(
            EvidenceSource.parse(part, EvidenceSource.SYSTEM)
            for part in as_text(row.get("evidence_sources")).split(",")
            if part.strip()
        )
        return Incident(
            id=as_int(row.get("id")),
            reference=as_text(row.get("reference")),
            title=as_text(row.get("title")),
            description=as_text(row.get("description")),
            category=ThreatCategory.parse(
                row.get("category"), ThreatCategory.UNCLASSIFIED
            ),
            severity=Severity.parse(row.get("severity"), Severity.MEDIUM),
            confidence=as_int(row.get("confidence")) or 0,
            status=IncidentStatus.parse(row.get("status"), IncidentStatus.NEW),
            src_ip=as_text(row.get("src_ip")),
            dst_ip=as_text(row.get("dst_ip")),
            dst_port=as_int(row.get("dst_port")),
            protocol=as_text(row.get("protocol")),
            affected_host_id=as_int(row.get("affected_host_id")),
            affected_host_ip=as_text(row.get("affected_host_ip")),
            affected_service=as_text(row.get("affected_service")),
            correlation_key=as_text(row.get("correlation_key")),
            evidence_sources=sources,
            event_count=as_int(row.get("event_count")) or 0,
            snort_alert_count=as_int(row.get("snort_alert_count")) or 0,
            anomaly_count=as_int(row.get("anomaly_count")) or 0,
            finding_count=as_int(row.get("finding_count")) or 0,
            risk_score=as_int(row.get("risk_score")) or 0,
            risk_rationale=as_text(row.get("risk_rationale")),
            detection_latency_seconds=as_float(row.get("detection_latency_seconds")),
            first_seen=as_dt(row.get("first_seen")),
            last_seen=as_dt(row.get("last_seen")),
            created_at=as_dt(row.get("created_at")),
            updated_at=as_dt(row.get("updated_at")),
            resolved_at=as_dt(row.get("resolved_at")),
            assigned_user_id=as_int(row.get("assigned_user_id")),
            assigned_username=as_text(row.get("assigned_username")),
            mitigation_id=as_int(row.get("mitigation_id")),
            evaluation=EvaluationLabel.parse(
                row.get("evaluation"), EvaluationLabel.UNCLASSIFIED
            ),
            evaluated_by=as_int(row.get("evaluated_by")),
            evaluated_at=as_dt(row.get("evaluated_at")),
            viewed_at=as_dt(row.get("viewed_at")),
            viewed_by=as_int(row.get("viewed_by")),
        )

    @staticmethod
    def _map_event(row: dict[str, Any]) -> IncidentEvent:
        """Map a row to :class:`IncidentEvent`."""
        return IncidentEvent(
            id=as_int(row.get("id")),
            incident_id=as_int(row.get("incident_id")),
            source=EvidenceSource.parse(row.get("source"), EvidenceSource.CORRELATION),
            event_type=as_text(row.get("event_type")),
            reference_table=as_text(row.get("reference_table")),
            reference_id=as_int(row.get("reference_id")),
            occurred_at=as_dt(row.get("occurred_at")),
            summary=as_text(row.get("summary")),
            detail=as_text(row.get("detail")),
            created_at=as_dt(row.get("created_at")),
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def next_reference(self) -> str:
        """Generate the next human-facing incident reference (``INC-000123``)."""
        value = self.db.query_value("SELECT COALESCE(MAX(id), 0) FROM incidents", default=0)
        return f"INC-{int(value or 0) + 1:06d}"

    def create(self, incident: Incident) -> int:
        """Insert a new incident and return its id."""
        now = utcnow()
        return self.db.insert(
            "INSERT INTO incidents (reference, title, description, category, "
            "severity, confidence, status, src_ip, dst_ip, dst_port, protocol, "
            "affected_host_id, affected_host_ip, affected_service, "
            "correlation_key, evidence_sources, event_count, "
            "snort_alert_count, anomaly_count, finding_count, risk_score, "
            "risk_rationale, detection_latency_seconds, first_seen, last_seen, "
            "created_at, updated_at, mitigation_id, evaluation) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                incident.reference[:32], incident.title[:190],
                incident.description, str(incident.category),
                str(incident.severity), max(0, min(100, incident.confidence)),
                str(incident.status), incident.src_ip[:45], incident.dst_ip[:45],
                incident.dst_port, incident.protocol[:16],
                incident.affected_host_id, incident.affected_host_ip[:45],
                incident.affected_service[:64], incident.correlation_key[:190],
                ",".join(str(s) for s in incident.evidence_sources)[:96],
                incident.event_count, incident.snort_alert_count,
                incident.anomaly_count, incident.finding_count,
                incident.risk_score, incident.risk_rationale,
                incident.detection_latency_seconds,
                to_db(incident.first_seen or now), to_db(incident.last_seen or now),
                to_db(incident.created_at or now), to_db(now),
                incident.mitigation_id, str(incident.evaluation),
            ),
        )

    def update_correlation_state(
        self,
        incident_id: int,
        *,
        severity: Severity,
        confidence: int,
        risk_score: int,
        risk_rationale: str,
        evidence_sources: tuple[EvidenceSource, ...],
        event_count: int,
        snort_alert_count: int,
        anomaly_count: int,
        finding_count: int,
        last_seen: datetime,
        description: str,
        mitigation_id: int | None,
    ) -> None:
        """Refresh an incident after new evidence was attached."""
        self.db.execute(
            "UPDATE incidents SET severity = %s, confidence = %s, "
            "risk_score = %s, risk_rationale = %s, evidence_sources = %s, "
            "event_count = %s, snort_alert_count = %s, anomaly_count = %s, "
            "finding_count = %s, last_seen = GREATEST(last_seen, %s), "
            "description = %s, mitigation_id = COALESCE(%s, mitigation_id), "
            "updated_at = %s WHERE id = %s",
            (
                str(severity), max(0, min(100, confidence)), risk_score,
                risk_rationale, ",".join(str(s) for s in evidence_sources)[:96],
                event_count, snort_alert_count, anomaly_count, finding_count,
                to_db(last_seen), description, mitigation_id,
                to_db(utcnow()), incident_id,
            ),
        )

    def add_event(self, event: IncidentEvent) -> int:
        """Attach one evidence event; duplicates are ignored (§26)."""
        return self.db.execute(
            "INSERT INTO incident_events (incident_id, source, event_type, "
            "reference_table, reference_id, occurred_at, summary, detail, "
            "created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE summary = VALUES(summary)",
            (
                event.incident_id, str(event.source), event.event_type[:48],
                event.reference_table[:48], event.reference_id,
                to_db(event.occurred_at), event.summary[:512], event.detail,
                to_db(event.created_at or utcnow()),
            ),
        )

    def set_status(
        self, incident_id: int, status: IncidentStatus, user_id: int | None = None
    ) -> None:
        """Change incident status, stamping ``resolved_at`` when appropriate."""
        resolved = (
            to_db(utcnow())
            if status
            in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE)
            else None
        )
        self.db.execute(
            "UPDATE incidents SET status = %s, resolved_at = %s, "
            "assigned_user_id = COALESCE(%s, assigned_user_id), updated_at = %s "
            "WHERE id = %s",
            (str(status), resolved, user_id, to_db(utcnow()), incident_id),
        )

    def assign(self, incident_id: int, user_id: int | None) -> None:
        """Assign or unassign an incident owner."""
        self.db.execute(
            "UPDATE incidents SET assigned_user_id = %s, updated_at = %s WHERE id = %s",
            (user_id, to_db(utcnow()), incident_id),
        )

    def set_evaluation(
        self, incident_id: int, evaluation: EvaluationLabel, user_id: int | None
    ) -> None:
        """Record an evaluator's classification of the incident (§82)."""
        self.db.execute(
            "UPDATE incidents SET evaluation = %s, evaluated_by = %s, "
            "evaluated_at = %s, updated_at = %s WHERE id = %s",
            (str(evaluation), user_id, to_db(utcnow()), to_db(utcnow()), incident_id),
        )

    def set_mitigation(self, incident_id: int, recommendation_id: int) -> None:
        """Attach a mitigation recommendation to an incident."""
        self.db.execute(
            "UPDATE incidents SET mitigation_id = %s, updated_at = %s WHERE id = %s",
            (recommendation_id, to_db(utcnow()), incident_id),
        )

    def add_note(self, incident_id: int, user_id: int | None, note: str) -> int:
        """Append an investigation note."""
        return self.db.insert(
            "INSERT INTO incident_notes (incident_id, user_id, note, created_at) "
            "VALUES (%s, %s, %s, %s)",
            (incident_id, user_id, note, to_db(utcnow())),
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get(self, incident_id: int) -> Incident | None:
        """Fetch one incident without its evidence."""
        row = self.db.query_one(f"{_SELECT} WHERE i.id = %s", (incident_id,))
        return self._map(row) if row else None

    def get_with_evidence(self, incident_id: int) -> Incident | None:
        """Fetch one incident with events and notes attached."""
        incident = self.get(incident_id)
        if not incident:
            return None
        incident.events = self.events_for(incident_id)
        incident.notes = self.notes_for(incident_id)
        return incident

    def find_open_by_correlation_key(
        self, correlation_key: str, since: datetime, include_resolved: bool = False
    ) -> Incident | None:
        """Find an incident to attach new evidence to (§26 aggregation window)."""
        status_clause = (
            "" if include_resolved
            else "AND i.status IN ('NEW','INVESTIGATING','ACKNOWLEDGED') "
        )
        row = self.db.query_one(
            f"{_SELECT} WHERE i.correlation_key = %s {status_clause}"
            "AND i.last_seen >= %s ORDER BY i.last_seen DESC LIMIT 1",
            (correlation_key[:190], to_db(since)),
        )
        return self._map(row) if row else None

    def events_for(self, incident_id: int) -> list[IncidentEvent]:
        """Evidence events attached to an incident, oldest first."""
        rows = self.db.query(
            "SELECT id, incident_id, source, event_type, reference_table, "
            "reference_id, occurred_at, summary, detail, created_at "
            "FROM incident_events WHERE incident_id = %s "
            "ORDER BY COALESCE(occurred_at, created_at) ASC LIMIT 2000",
            (incident_id,),
        )
        return self._map_all(rows, self._map_event)

    def notes_for(self, incident_id: int) -> list[IncidentNote]:
        """Analyst notes attached to an incident."""
        rows = self.db.query(
            "SELECT n.id, n.incident_id, n.user_id, n.note, n.created_at, "
            "u.username FROM incident_notes n "
            "LEFT JOIN users u ON u.id = n.user_id "
            "WHERE n.incident_id = %s ORDER BY n.created_at ASC LIMIT 500",
            (incident_id,),
        )
        return [
            IncidentNote(
                id=as_int(r["id"]),
                incident_id=as_int(r["incident_id"]),
                user_id=as_int(r["user_id"]),
                username=as_text(r["username"]),
                note=as_text(r["note"]),
                created_at=as_dt(r["created_at"]),
            )
            for r in rows
        ]

    def search(
        self,
        *,
        text: str = "",
        status: str = "",
        severity: str = "",
        category: str = "",
        src_ip: str = "",
        assigned_user_id: int | None = None,
        open_only: bool = False,
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "last_seen",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[Incident]:
        """Search incidents with validated filters."""
        query = QueryFilter(_FILTERABLE, prefix="i")
        query.equals("status", status)
        query.equals("severity", severity)
        query.equals("category", category)
        query.equals("src_ip", src_ip)
        query.equals("assigned_user_id", assigned_user_id)
        query.gte("created_at", to_db(start))
        query.lte("created_at", to_db(end))
        if open_only:
            query.raw("i.status IN ('NEW','INVESTIGATING','ACKNOWLEDGED')")
        query.any_of(("title", "src_ip", "dst_ip", "reference"), text)
        order = order_clause(sort_by, sort_dir, _SORTABLE, "last_seen", "i")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map)

    def recent(self, limit: int = 10) -> list[Incident]:
        """Newest incidents for the dashboard."""
        rows = self.db.query(
            f"{_SELECT} ORDER BY i.created_at DESC LIMIT %s",
            (max(1, min(int(limit), 200)),),
        )
        return self._map_all(rows, self._map)

    def for_host(self, host_id: int, limit: int = 100) -> list[Incident]:
        """Incidents affecting a host."""
        rows = self.db.query(
            f"{_SELECT} WHERE i.affected_host_id = %s "
            "ORDER BY i.last_seen DESC LIMIT %s",
            (host_id, max(1, min(int(limit), 1000))),
        )
        return self._map_all(rows, self._map)

    def count_open(self) -> int:
        """Incidents still requiring attention."""
        return self.count(
            f"SELECT COUNT(*) FROM incidents WHERE status IN {_OPEN_STATUSES}"
        )

    def count_unread(self) -> int:
        """Open incidents nobody has opened in the investigation view yet.

        This is what the sidebar counter reports. Counting every open incident
        instead meant the badge never moved while an analyst worked through
        them, which is the opposite of what a notification count is for.
        """
        return self.count(
            "SELECT COUNT(*) FROM incidents "
            f"WHERE viewed_at IS NULL AND status IN {_OPEN_STATUSES}"
        )

    def mark_viewed(self, incident_id: int, user_id: int | None) -> bool:
        """Stamp an incident as read the first time it is opened.

        Returns:
            True when this call was the one that marked it, so the caller can
            refresh a counter only when something actually changed.
        """
        changed = self.db.execute(
            "UPDATE incidents SET viewed_at = %s, viewed_by = %s "
            "WHERE id = %s AND viewed_at IS NULL",
            (to_db(utcnow()), user_id, incident_id),
        )
        return bool(changed)

    def mark_all_viewed(self, user_id: int | None) -> int:
        """Stamp every unread incident as read in one go.

        Used by the sidebar's "mark all read" - it clears the whole backlog
        at once rather than requiring each incident to be opened individually.
        """
        return self.db.execute(
            "UPDATE incidents SET viewed_at = %s, viewed_by = %s "
            "WHERE viewed_at IS NULL",
            (to_db(utcnow()), user_id),
        )

    def count_all(self) -> int:
        """Total incidents recorded."""
        return self.count("SELECT COUNT(*) FROM incidents")

    def count_by_severity(self, open_only: bool = True) -> dict[str, int]:
        """Incident counts grouped by severity."""
        where = (
            "WHERE status IN ('NEW','INVESTIGATING','ACKNOWLEDGED')"
            if open_only
            else ""
        )
        rows = self.db.query(
            f"SELECT severity, COUNT(*) AS c FROM incidents {where} GROUP BY severity"
        )
        return {as_text(r["severity"]): as_int(r["c"]) or 0 for r in rows}

    def count_by_category(self, since: datetime | None = None) -> dict[str, int]:
        """Incident counts grouped by threat category."""
        if since:
            rows = self.db.query(
                "SELECT category, COUNT(*) AS c FROM incidents "
                "WHERE created_at >= %s GROUP BY category",
                (to_db(since),),
            )
        else:
            rows = self.db.query(
                "SELECT category, COUNT(*) AS c FROM incidents GROUP BY category"
            )
        return {as_text(r["category"]): as_int(r["c"]) or 0 for r in rows}

    def timeline(self, since: datetime, limit: int = 100) -> list[dict[str, Any]]:
        """Incident events ordered for the dashboard threat timeline."""
        rows = self.db.query(
            "SELECT i.reference, i.title, i.severity, i.category, i.src_ip, "
            "i.dst_ip, i.first_seen, i.last_seen, i.status FROM incidents i "
            "WHERE i.last_seen >= %s ORDER BY i.last_seen DESC LIMIT %s",
            (to_db(since), max(1, min(int(limit), 500))),
        )
        return [
            {
                "reference": as_text(r["reference"]),
                "title": as_text(r["title"]),
                "severity": as_text(r["severity"]),
                "category": as_text(r["category"]),
                "src_ip": as_text(r["src_ip"]),
                "dst_ip": as_text(r["dst_ip"]),
                "first_seen": as_dt(r["first_seen"]),
                "last_seen": as_dt(r["last_seen"]),
                "status": as_text(r["status"]),
            }
            for r in rows
        ]

    def evaluation_counts(self) -> dict[str, int]:
        """Counts per analyst evaluation label."""
        rows = self.db.query(
            "SELECT evaluation, COUNT(*) AS c FROM incidents GROUP BY evaluation"
        )
        return {as_text(r["evaluation"]): as_int(r["c"]) or 0 for r in rows}

    def mean_detection_latency(self, since: datetime) -> float | None:
        """Mean recorded detection latency across incidents in a window."""
        value = self.db.query_value(
            "SELECT AVG(detection_latency_seconds) FROM incidents "
            "WHERE detection_latency_seconds IS NOT NULL AND created_at >= %s",
            (to_db(since),),
        )
        return as_float(value)
