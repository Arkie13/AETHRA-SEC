"""Snort alert and traffic-anomaly persistence (§22, §24, §43, §84)."""

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
    decode_json,
    encode_json,
    limit_clause,
    order_clause,
)
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import (
    AlertStatus,
    EvaluationLabel,
    EvidenceSource,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.utils.timeutil import to_db, utcnow

_ALERT_FILTERABLE = {
    "alert_time", "received_at", "signature_id", "generator_id", "severity",
    "status", "src_ip", "dst_ip", "dst_port", "protocol", "classification",
    "message", "priority", "incident_id", "evaluation", "transport",
}
_ALERT_SORTABLE = {
    "alert_time", "received_at", "id", "severity", "src_ip", "dst_ip",
    "signature_id", "priority", "status",
}
_ALERT_SELECT = (
    "SELECT id, alert_time, received_at, time_source, generator_id, "
    "signature_id, revision, message, classification, priority, severity, "
    "protocol, src_ip, src_port, dst_ip, dst_port, interface, sensor, "
    "transport, raw_alert, src_host_id, dst_host_id, incident_id, status, "
    "evaluation, evaluated_by, evaluated_at, duplicate_count, dedup_key, "
    "created_at FROM snort_alerts"
)

_ANOMALY_FILTERABLE = {
    "rule_id", "category", "severity", "src_ip", "dst_ip", "dst_port",
    "protocol", "created_at", "first_seen", "last_seen", "incident_id",
    "evaluation", "title", "observation", "interface", "host_id",
}
_ANOMALY_SORTABLE = {"created_at", "last_seen", "severity", "src_ip", "id"}
_ANOMALY_SELECT = (
    "SELECT id, rule_id, category, title, observation, why_it_matters, "
    "what_to_check, severity, confidence, src_ip, dst_ip, dst_port, protocol, "
    "interface, observed_value, threshold_value, window_seconds, event_count, "
    "first_seen, last_seen, evidence, host_id, incident_id, evaluation, "
    "source, created_at FROM traffic_anomalies"
)

class AlertRepository(Repository):
    """Persists real Snort alerts and deterministic traffic anomalies."""

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _map_alert(row: dict[str, Any]) -> SnortAlert:
        """Map a row to :class:`SnortAlert`."""
        return SnortAlert(
            id=as_int(row.get("id")),
            alert_time=as_dt(row.get("alert_time")),
            received_at=as_dt(row.get("received_at")),
            time_source=as_text(row.get("time_source")),
            generator_id=as_int(row.get("generator_id")),
            signature_id=as_int(row.get("signature_id")),
            revision=as_int(row.get("revision")),
            message=as_text(row.get("message")),
            classification=as_text(row.get("classification")),
            priority=as_int(row.get("priority")),
            severity=Severity.parse(row.get("severity"), Severity.MEDIUM),
            protocol=as_text(row.get("protocol")),
            src_ip=as_text(row.get("src_ip")),
            src_port=as_int(row.get("src_port")),
            dst_ip=as_text(row.get("dst_ip")),
            dst_port=as_int(row.get("dst_port")),
            interface=as_text(row.get("interface")),
            sensor=as_text(row.get("sensor")),
            transport=as_text(row.get("transport")),
            raw_alert=as_text(row.get("raw_alert")),
            src_host_id=as_int(row.get("src_host_id")),
            dst_host_id=as_int(row.get("dst_host_id")),
            incident_id=as_int(row.get("incident_id")),
            status=AlertStatus.parse(row.get("status"), AlertStatus.NEW),
            evaluation=EvaluationLabel.parse(
                row.get("evaluation"), EvaluationLabel.UNCLASSIFIED
            ),
            evaluated_by=as_int(row.get("evaluated_by")),
            evaluated_at=as_dt(row.get("evaluated_at")),
            duplicate_count=as_int(row.get("duplicate_count")) or 1,
            dedup_key=as_text(row.get("dedup_key")),
            created_at=as_dt(row.get("created_at")),
        )

    @staticmethod
    def _map_anomaly(row: dict[str, Any]) -> TrafficAnomaly:
        """Map a row to :class:`TrafficAnomaly`."""
        return TrafficAnomaly(
            id=as_int(row.get("id")),
            rule_id=as_text(row.get("rule_id")),
            category=ThreatCategory.parse(
                row.get("category"), ThreatCategory.UNCLASSIFIED
            ),
            title=as_text(row.get("title")),
            observation=as_text(row.get("observation")),
            why_it_matters=as_text(row.get("why_it_matters")),
            what_to_check=as_text(row.get("what_to_check")),
            severity=Severity.parse(row.get("severity"), Severity.MEDIUM),
            confidence=as_int(row.get("confidence")) or 0,
            src_ip=as_text(row.get("src_ip")),
            dst_ip=as_text(row.get("dst_ip")),
            dst_port=as_int(row.get("dst_port")),
            protocol=as_text(row.get("protocol")),
            interface=as_text(row.get("interface")),
            observed_value=as_float(row.get("observed_value")) or 0.0,
            threshold_value=as_float(row.get("threshold_value")) or 0.0,
            window_seconds=as_int(row.get("window_seconds")) or 0,
            event_count=as_int(row.get("event_count")) or 1,
            first_seen=as_dt(row.get("first_seen")),
            last_seen=as_dt(row.get("last_seen")),
            evidence=decode_json(row.get("evidence"), {}),
            host_id=as_int(row.get("host_id")),
            incident_id=as_int(row.get("incident_id")),
            evaluation=EvaluationLabel.parse(
                row.get("evaluation"), EvaluationLabel.UNCLASSIFIED
            ),
            source=EvidenceSource.parse(row.get("source"), EvidenceSource.PYSHARK),
            created_at=as_dt(row.get("created_at")),
        )

    # ------------------------------------------------------------------
    # Snort alerts
    # ------------------------------------------------------------------
    def find_duplicate(
        self, dedup_key: str, since: datetime
    ) -> tuple[int, int] | None:
        """Find a recent alert with the same dedup key.

        Returns:
            ``(alert_id, duplicate_count)`` when one exists inside the
            suppression window, else ``None``.
        """
        if not dedup_key:
            return None
        row = self.db.query_one(
            "SELECT id, duplicate_count FROM snort_alerts "
            "WHERE dedup_key = %s AND received_at >= %s "
            "ORDER BY received_at DESC LIMIT 1",
            (dedup_key[:190], to_db(since)),
        )
        if not row:
            return None
        return int(row["id"]), int(row["duplicate_count"] or 1)

    def increment_duplicate(self, alert_id: int, observed_at: datetime) -> None:
        """Record another occurrence of an already-stored alert (§92)."""
        self.db.execute(
            "UPDATE snort_alerts SET duplicate_count = duplicate_count + 1, "
            "received_at = %s WHERE id = %s",
            (to_db(observed_at), alert_id),
        )

    def insert_alert(self, alert: SnortAlert) -> int:
        """Insert one real Snort alert and return its id."""
        return self.db.insert(
            "INSERT INTO snort_alerts (alert_time, received_at, time_source, "
            "generator_id, signature_id, revision, message, classification, "
            "priority, severity, protocol, src_ip, src_port, dst_ip, dst_port, "
            "interface, sensor, transport, raw_alert, src_host_id, dst_host_id, "
            "status, evaluation, duplicate_count, dedup_key, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                to_db(alert.alert_time), to_db(alert.received_at or utcnow()),
                alert.time_source[:16], alert.generator_id, alert.signature_id,
                alert.revision, alert.message[:512], alert.classification[:128],
                alert.priority, str(alert.severity), alert.protocol[:16],
                alert.src_ip[:45], alert.src_port, alert.dst_ip[:45],
                alert.dst_port, alert.interface[:96], alert.sensor[:96],
                alert.transport[:16], alert.raw_alert, alert.src_host_id,
                alert.dst_host_id, str(alert.status), str(alert.evaluation),
                alert.duplicate_count, alert.dedup_key[:190],
                to_db(alert.created_at or utcnow()),
            ),
        )

    def get_alert(self, alert_id: int) -> SnortAlert | None:
        """Fetch one alert."""
        row = self.db.query_one(f"{_ALERT_SELECT} WHERE id = %s", (alert_id,))
        return self._map_alert(row) if row else None

    def search_alerts(
        self,
        *,
        text: str = "",
        severity: str = "",
        status: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        protocol: str = "",
        signature_id: int | None = None,
        evaluation: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "received_at",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[SnortAlert]:
        """Search stored alerts with validated filters."""
        query = QueryFilter(_ALERT_FILTERABLE)
        query.equals("severity", severity)
        query.equals("status", status)
        query.equals("src_ip", src_ip)
        query.equals("dst_ip", dst_ip)
        query.equals("protocol", protocol)
        query.equals("signature_id", signature_id)
        query.equals("evaluation", evaluation)
        query.gte("received_at", to_db(start))
        query.lte("received_at", to_db(end))
        query.any_of(("message", "classification", "src_ip", "dst_ip"), text)
        order = order_clause(sort_by, sort_dir, _ALERT_SORTABLE, "received_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_ALERT_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map_alert)

    def recent_alerts(self, limit: int = 10) -> list[SnortAlert]:
        """Newest alerts for the dashboard widget."""
        rows = self.db.query(
            f"{_ALERT_SELECT} ORDER BY received_at DESC LIMIT %s",
            (max(1, min(int(limit), 200)),),
        )
        return self._map_all(rows, self._map_alert)

    def alerts_for_host(self, host_id: int, limit: int = 100) -> list[SnortAlert]:
        """Alerts where a host was source or destination."""
        rows = self.db.query(
            f"{_ALERT_SELECT} WHERE src_host_id = %s OR dst_host_id = %s "
            "ORDER BY received_at DESC LIMIT %s",
            (host_id, host_id, max(1, min(int(limit), 2000))),
        )
        return self._map_all(rows, self._map_alert)

    def alerts_for_incident(self, incident_id: int) -> list[SnortAlert]:
        """Alerts attached to one incident."""
        rows = self.db.query(
            f"{_ALERT_SELECT} WHERE incident_id = %s ORDER BY received_at ASC",
            (incident_id,),
        )
        return self._map_all(rows, self._map_alert)

    def uncorrelated_alerts(self, since: datetime, limit: int = 500) -> list[SnortAlert]:
        """Alerts not yet attached to an incident, oldest first."""
        rows = self.db.query(
            f"{_ALERT_SELECT} WHERE incident_id IS NULL AND received_at >= %s "
            "ORDER BY received_at ASC LIMIT %s",
            (to_db(since), max(1, min(int(limit), 5000))),
        )
        return self._map_all(rows, self._map_alert)

    def set_alert_incident(self, alert_id: int, incident_id: int) -> None:
        """Attach an alert to an incident."""
        self.db.execute(
            "UPDATE snort_alerts SET incident_id = %s WHERE id = %s",
            (incident_id, alert_id),
        )

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> None:
        """Change an alert's analyst workflow status."""
        self.db.execute(
            "UPDATE snort_alerts SET status = %s WHERE id = %s",
            (str(status), alert_id),
        )

    def mark_all_new_reviewed(self) -> int:
        """Move every alert still in NEW to REVIEWED, and report how many.

        Used by the sidebar's "mark all read" - it reviews the whole backlog
        at once rather than one row at a time, without touching alerts an
        analyst already acted on.
        """
        return self.db.execute(
            "UPDATE snort_alerts SET status = %s WHERE status = 'NEW'",
            (str(AlertStatus.REVIEWED),),
        )

    def set_alert_evaluation(
        self, alert_id: int, evaluation: EvaluationLabel, user_id: int | None
    ) -> None:
        """Record an evaluator's true/false-positive classification (§82)."""
        self.db.execute(
            "UPDATE snort_alerts SET evaluation = %s, evaluated_by = %s, "
            "evaluated_at = %s WHERE id = %s",
            (str(evaluation), user_id, to_db(utcnow()), alert_id),
        )

    def count_alerts(self) -> int:
        """Total stored alerts."""
        return self.count("SELECT COUNT(*) FROM snort_alerts")

    def count_alerts_since(self, since: datetime) -> int:
        """Alerts received since a point in time."""
        return self.count(
            "SELECT COUNT(*) FROM snort_alerts WHERE received_at >= %s",
            (to_db(since),),
        )

    def count_alerts_between(self, start: datetime, end: datetime) -> int:
        """Alerts received inside a window."""
        return self.count(
            "SELECT COUNT(*) FROM snort_alerts "
            "WHERE received_at >= %s AND received_at < %s",
            (to_db(start), to_db(end)),
        )

    def earliest_alert_time(self) -> datetime | None:
        """When the oldest retained alert was received, if there is one."""
        return as_dt(self.db.query_value("SELECT MIN(received_at) FROM snort_alerts"))

    def count_by_severity(self, since: datetime | None = None) -> dict[str, int]:
        """Alert counts grouped by severity."""
        if since:
            rows = self.db.query(
                "SELECT severity, COUNT(*) AS c FROM snort_alerts "
                "WHERE received_at >= %s GROUP BY severity",
                (to_db(since),),
            )
        else:
            rows = self.db.query(
                "SELECT severity, COUNT(*) AS c FROM snort_alerts GROUP BY severity"
            )
        return {as_text(r["severity"]): as_int(r["c"]) or 0 for r in rows}

    def alerts_per_interval(
        self, start: datetime, end: datetime, minutes: int = 5
    ) -> list[tuple[datetime, int]]:
        """Alert counts bucketed into fixed intervals for the IDS chart."""
        bucket = max(1, min(int(minutes), 1440))
        rows = self.db.query(
            "SELECT FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(received_at) / %s) * %s) "
            "AS bucket, COUNT(*) AS c FROM snort_alerts "
            "WHERE received_at >= %s AND received_at <= %s "
            "GROUP BY bucket ORDER BY bucket ASC LIMIT 2000",
            (bucket * 60, bucket * 60, to_db(start), to_db(end)),
        )
        result: list[tuple[datetime, int]] = []
        for row in rows:
            stamp = as_dt(row["bucket"])
            if stamp:
                result.append((stamp, as_int(row["c"]) or 0))
        return result

    def last_alert_time(self) -> datetime | None:
        """Timestamp of the most recently received alert."""
        return as_dt(self.db.query_value("SELECT MAX(received_at) FROM snort_alerts"))

    def reliability_counters(self) -> dict[str, int]:
        """Alert reliability statistics computed from stored rows (§84)."""
        row = self.db.query_one(
            "SELECT COUNT(*) AS stored, "
            "COALESCE(SUM(duplicate_count - 1), 0) AS duplicates, "
            "COALESCE(SUM(incident_id IS NOT NULL), 0) AS correlated, "
            "COALESCE(SUM(status = 'NEW'), 0) AS unresolved FROM snort_alerts"
        )
        if not row:
            return {"stored": 0, "duplicates": 0, "correlated": 0, "unresolved": 0}
        return {
            "stored": as_int(row["stored"]) or 0,
            "duplicates": as_int(row["duplicates"]) or 0,
            "correlated": as_int(row["correlated"]) or 0,
            "unresolved": as_int(row["unresolved"]) or 0,
        }

    def evaluation_counts(self) -> dict[str, int]:
        """Counts per analyst evaluation label (§82)."""
        rows = self.db.query(
            "SELECT evaluation, COUNT(*) AS c FROM snort_alerts GROUP BY evaluation"
        )
        return {as_text(r["evaluation"]): as_int(r["c"]) or 0 for r in rows}

    def mean_detection_latency(self, since: datetime) -> float | None:
        """Mean seconds between Snort's event time and our ingest time.

        Only rows where Snort supplied its own timestamp are included, so the
        measurement never rests on an invented value (§81).
        """
        value = self.db.query_value(
            "SELECT AVG(TIMESTAMPDIFF(MICROSECOND, alert_time, received_at)) "
            "FROM snort_alerts WHERE alert_time IS NOT NULL AND received_at >= %s",
            (to_db(since),),
        )
        if value is None:
            return None
        try:
            return max(0.0, float(value) / 1_000_000.0)
        except (TypeError, ValueError):
            return None

    def prune_alerts_before(self, cutoff: datetime) -> int:
        """Delete alerts older than ``cutoff`` that are not linked to incidents."""
        return self.db.execute(
            "DELETE FROM snort_alerts WHERE received_at < %s AND incident_id IS NULL",
            (to_db(cutoff),),
        )

    # ------------------------------------------------------------------
    # Traffic anomalies
    # ------------------------------------------------------------------
    def recent_anomaly(
        self, dedup_key_parts: tuple[str, str, str, int | None], since: datetime
    ) -> TrafficAnomaly | None:
        """Find a matching anomaly inside the suppression window (§92)."""
        rule_id, src_ip, dst_ip, dst_port = dedup_key_parts
        clauses = ["rule_id = %s", "src_ip = %s", "dst_ip = %s", "last_seen >= %s"]
        params: list[Any] = [rule_id, src_ip, dst_ip, to_db(since)]
        if dst_port is None:
            clauses.append("dst_port IS NULL")
        else:
            clauses.append("dst_port = %s")
            params.append(dst_port)
        row = self.db.query_one(
            f"{_ANOMALY_SELECT} WHERE {' AND '.join(clauses)} "
            "ORDER BY last_seen DESC LIMIT 1",
            params,
        )
        return self._map_anomaly(row) if row else None

    def insert_anomaly(self, anomaly: TrafficAnomaly) -> int:
        """Insert one deterministic traffic anomaly."""
        now = utcnow()
        return self.db.insert(
            "INSERT INTO traffic_anomalies (rule_id, category, title, "
            "observation, why_it_matters, what_to_check, severity, confidence, "
            "src_ip, dst_ip, dst_port, protocol, interface, observed_value, "
            "threshold_value, window_seconds, event_count, first_seen, "
            "last_seen, evidence, host_id, evaluation, source, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                anomaly.rule_id[:48], str(anomaly.category), anomaly.title[:190],
                anomaly.observation, anomaly.why_it_matters,
                anomaly.what_to_check, str(anomaly.severity),
                max(0, min(100, anomaly.confidence)), anomaly.src_ip[:45],
                anomaly.dst_ip[:45], anomaly.dst_port, anomaly.protocol[:16],
                anomaly.interface[:96], round(anomaly.observed_value, 3),
                round(anomaly.threshold_value, 3), anomaly.window_seconds,
                anomaly.event_count, to_db(anomaly.first_seen or now),
                to_db(anomaly.last_seen or now), encode_json(anomaly.evidence),
                anomaly.host_id, str(anomaly.evaluation), str(anomaly.source),
                to_db(anomaly.created_at or now),
            ),
        )

    def update_anomaly_occurrence(
        self, anomaly_id: int, *, last_seen: datetime, observed_value: float
    ) -> None:
        """Fold a repeat observation into an existing anomaly record."""
        self.db.execute(
            "UPDATE traffic_anomalies SET event_count = event_count + 1, "
            "last_seen = %s, observed_value = GREATEST(observed_value, %s) "
            "WHERE id = %s",
            (to_db(last_seen), round(observed_value, 3), anomaly_id),
        )

    def get_anomaly(self, anomaly_id: int) -> TrafficAnomaly | None:
        """Fetch one anomaly."""
        row = self.db.query_one(f"{_ANOMALY_SELECT} WHERE id = %s", (anomaly_id,))
        return self._map_anomaly(row) if row else None

    def search_anomalies(
        self,
        *,
        text: str = "",
        severity: str = "",
        category: str = "",
        src_ip: str = "",
        rule_id: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "created_at",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[TrafficAnomaly]:
        """Search recorded traffic anomalies."""
        query = QueryFilter(_ANOMALY_FILTERABLE)
        query.equals("severity", severity)
        query.equals("category", category)
        query.equals("src_ip", src_ip)
        query.equals("rule_id", rule_id)
        query.gte("created_at", to_db(start))
        query.lte("created_at", to_db(end))
        query.any_of(("title", "observation", "src_ip", "dst_ip"), text)
        order = order_clause(sort_by, sort_dir, _ANOMALY_SORTABLE, "created_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_ANOMALY_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map_anomaly)

    def uncorrelated_anomalies(
        self, since: datetime, limit: int = 500
    ) -> list[TrafficAnomaly]:
        """Anomalies not yet attached to an incident."""
        rows = self.db.query(
            f"{_ANOMALY_SELECT} WHERE incident_id IS NULL AND last_seen >= %s "
            "ORDER BY first_seen ASC LIMIT %s",
            (to_db(since), max(1, min(int(limit), 5000))),
        )
        return self._map_all(rows, self._map_anomaly)

    def anomalies_for_incident(self, incident_id: int) -> list[TrafficAnomaly]:
        """Anomalies attached to one incident."""
        rows = self.db.query(
            f"{_ANOMALY_SELECT} WHERE incident_id = %s ORDER BY first_seen ASC",
            (incident_id,),
        )
        return self._map_all(rows, self._map_anomaly)

    def set_anomaly_incident(self, anomaly_id: int, incident_id: int) -> None:
        """Attach an anomaly to an incident."""
        self.db.execute(
            "UPDATE traffic_anomalies SET incident_id = %s WHERE id = %s",
            (incident_id, anomaly_id),
        )

    def count_anomalies_since(self, since: datetime) -> int:
        """Anomalies recorded since a point in time."""
        return self.count(
            "SELECT COUNT(*) FROM traffic_anomalies WHERE created_at >= %s",
            (to_db(since),),
        )

    def recent_anomalies(self, limit: int = 10) -> list[TrafficAnomaly]:
        """Newest anomalies for the dashboard."""
        rows = self.db.query(
            f"{_ANOMALY_SELECT} ORDER BY created_at DESC LIMIT %s",
            (max(1, min(int(limit), 200)),),
        )
        return self._map_all(rows, self._map_anomaly)

    def prune_anomalies_before(self, cutoff: datetime) -> int:
        """Delete unlinked anomalies older than ``cutoff``."""
        return self.db.execute(
            "DELETE FROM traffic_anomalies WHERE created_at < %s "
            "AND incident_id IS NULL",
            (to_db(cutoff),),
        )
