"""Snort alert and traffic-anomaly persistence (§22, §24, §43, §84)."""

from __future__ import annotations

import json
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
    period_bounds,
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
    "last_alert_time, peak_pps, created_at FROM snort_alerts"
)

_ANOMALY_FILTERABLE = {
    "rule_id", "category", "severity", "src_ip", "dst_ip", "dst_port",
    "protocol", "created_at", "first_seen", "last_seen", "incident_id",
    "evaluation", "title", "observation", "interface", "host_id",
    # The read receipt, so an "unreviewed" count can be filtered in SQL
    # instead of being tallied from a truncated page of rows.
    "reviewed_at",
}
_ANOMALY_SORTABLE = {"created_at", "last_seen", "severity", "src_ip", "id"}
_ANOMALY_SELECT = (
    "SELECT id, rule_id, category, title, observation, why_it_matters, "
    "what_to_check, severity, confidence, src_ip, dst_ip, dst_port, protocol, "
    "interface, observed_value, latest_value, latest_measured_at, "
    "threshold_value, window_seconds, event_count, peak_severity, "
    "detected_at, reviewed_at, reviewed_by, first_seen, last_seen, evidence, "
    "host_id, incident_id, evaluation, "
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
            last_alert_time=as_dt(row.get("last_alert_time")),
            peak_pps=(
                as_float(row.get("peak_pps"))
                if row.get("peak_pps") is not None else None
            ),
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
            latest_value=(
                float(row["latest_value"])
                if row.get("latest_value") is not None else None
            ),
            latest_measured_at=as_dt(row.get("latest_measured_at")),
            peak_severity=(
                Severity.parse(row.get("peak_severity"), Severity.MEDIUM)
                if row.get("peak_severity") else None
            ),
            detected_at=as_dt(row.get("detected_at")),
            reviewed_at=as_dt(row.get("reviewed_at")),
            reviewed_by=as_int(row.get("reviewed_by")),
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
        self, dedup_key: str, since: datetime, *, event_since: datetime | None = None
    ) -> tuple[int, int] | None:
        """Find a recent alert with the same dedup key.

        Args:
            since: ingest-time bound (``received_at``), as before.
            event_since: when given, the alert's own most recent sensor time
                (``last_alert_time``, else ``alert_time``) must also be at or
                after it. This is the episode boundary: a repeat only extends
                an alert whose traffic was seen within the episode gap. Bounded
                by ingest time alone, every repeat moved ``received_at``
                forward, so test runs less than two minutes apart folded into
                one row for ever - Snort row 3707 holds 7,729 "ICMP echo
                request" repeats.

        Returns:
            ``(alert_id, duplicate_count)`` when one exists, else ``None``.
        """
        if not dedup_key:
            return None
        clause = ""
        params: list[Any] = [dedup_key[:190], to_db(since)]
        if event_since is not None:
            clause = "AND COALESCE(last_alert_time, alert_time, received_at) >= %s "
            params.append(to_db(event_since))
        row = self.db.query_one(
            "SELECT id, duplicate_count FROM snort_alerts "
            f"WHERE dedup_key = %s AND received_at >= %s {clause}"
            "ORDER BY received_at DESC LIMIT 1",
            tuple(params),
        )
        if not row:
            return None
        return int(row["id"]), int(row["duplicate_count"] or 1)

    def find_identical(self, raw_alert: str) -> tuple[int, int] | None:
        """Find a stored alert that is byte-for-byte the same Snort event.

        This is *idempotency*, which is a different question from suppression.
        :meth:`find_duplicate` asks "has this signature fired again recently?"
        and is deliberately time-bounded. This asks "have I already ingested
        this exact log line?", and must not be time-bounded at all: a Snort
        alert file that is re-read - after a pipeline restart, or when a
        capture chunk is processed twice - replays events that are minutes or
        hours old, and every one of them was previously stored again as a new
        alert and correlated into a second incident.

        A Snort alert line carries its own timestamp, so identical text means
        the same event rather than a recurrence.
        """
        if not raw_alert:
            return None
        row = self.db.query_one(
            "SELECT id, duplicate_count FROM snort_alerts "
            "WHERE raw_alert = %s ORDER BY id LIMIT 1",
            (raw_alert,),
        )
        if not row:
            return None
        return int(row["id"]), int(row["duplicate_count"] or 1)

    def increment_duplicate(
        self,
        alert_id: int,
        observed_at: datetime,
        alert_time: datetime | None = None,
    ) -> None:
        """Record another occurrence of an already-stored alert (§92).

        Args:
            observed_at: when AETHRA-SEC ingested this repeat. Kept in
                ``received_at``, which is what that column has always meant.
            alert_time: the Snort timestamp on the repeat itself - when the
                sensor saw the traffic. Stored in ``last_alert_time``, and
                advanced only forwards, so re-reading an older alert file
                cannot drag an episode's last-observed time backwards.

        Before ``last_alert_time`` existed the repeat's own timestamp was
        dropped here, which left a folded row able to say how often something
        fired but not when it last fired.
        """
        if alert_time is None:
            self.db.execute(
                "UPDATE snort_alerts SET duplicate_count = duplicate_count + 1, "
                "received_at = %s WHERE id = %s",
                (to_db(observed_at), alert_id),
            )
            return
        self.db.execute(
            "UPDATE snort_alerts SET duplicate_count = duplicate_count + 1, "
            "received_at = %s, "
            "last_alert_time = GREATEST(COALESCE(last_alert_time, %s), %s) "
            "WHERE id = %s",
            (to_db(observed_at), to_db(alert_time), to_db(alert_time), alert_id),
        )

    def insert_alert(self, alert: SnortAlert) -> int:
        """Insert one real Snort alert and return its id."""
        return self.db.insert(
            "INSERT INTO snort_alerts (alert_time, received_at, time_source, "
            "generator_id, signature_id, revision, message, classification, "
            "priority, severity, protocol, src_ip, src_port, dst_ip, dst_port, "
            "interface, sensor, transport, raw_alert, src_host_id, dst_host_id, "
            "status, evaluation, duplicate_count, dedup_key, last_alert_time, "
            "peak_pps, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
                # A first sighting's last-observed time is its own timestamp.
                to_db(alert.last_alert_time or alert.alert_time),
                (
                    round(float(alert.peak_pps), 1)
                    if alert.peak_pps is not None else None
                ),
                to_db(alert.created_at or utcnow()),
            ),
        )

    def raise_alert_grade(
        self, alert_id: int, packets_per_second: float, severity: "Severity"
    ) -> None:
        """Raise a Snort alert's recorded pps and severity, never lowering them.

        A repeat of an alert that is still active is measured again; when its
        source is now sending faster, both the pps and the severity graded from
        it on the §3.9.8 legend rise. One statement, so a slower concurrent
        fold cannot lower either.
        """
        ladder = "'INFO','LOW','MEDIUM','HIGH','CRITICAL'"
        value = str(severity)
        self.db.execute(
            "UPDATE snort_alerts SET "
            "peak_pps = GREATEST(COALESCE(peak_pps, 0), %s), "
            "severity = IF(FIELD(%s, " + ladder + ") > "
            "FIELD(COALESCE(severity, %s), " + ladder + "), %s, severity) "
            "WHERE id = %s",
            (round(float(packets_per_second), 1), value, value, value, alert_id),
        )

    def get_alert(self, alert_id: int) -> SnortAlert | None:
        """Fetch one alert."""
        row = self.db.query_one(f"{_ALERT_SELECT} WHERE id = %s", (alert_id,))
        return self._map_alert(row) if row else None

    @staticmethod
    def _alert_filter(
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
    ) -> QueryFilter:
        """The WHERE clause for an alert search.

        Extracted so that the rows a screen displays and the counts printed
        above them are selected by *the same* predicate. When the summary was
        tallied from the returned rows instead, the row limit silently became
        part of the count: 1,000 rows returned out of 1,412 matching, and a
        summary that disagreed with the dashboard by exactly the 412 it never
        saw.
        """
        query = QueryFilter(_ALERT_FILTERABLE)
        query.equals("severity", severity)
        query.equals("status", status)
        query.equals("src_ip", src_ip)
        query.equals("dst_ip", dst_ip)
        query.equals("protocol", protocol)
        query.equals("signature_id", signature_id)
        query.equals("evaluation", evaluation)
        query.gte("received_at", to_db(start))
        # Exclusive, matching the Dashboard's half-open reporting period.
        query.lt("received_at", to_db(end))
        query.any_of(("message", "classification", "src_ip", "dst_ip"), text)
        return query

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
        query = self._alert_filter(
            text=text, severity=severity, status=status, src_ip=src_ip,
            dst_ip=dst_ip, protocol=protocol, signature_id=signature_id,
            evaluation=evaluation, start=start, end=end,
        )
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

    def count_alerts_in_period(
        self, start: datetime | None, end: datetime | None = None
    ) -> int:
        """Snort alerts received inside ``[start, end)``.

        ``start`` of ``None`` means everything up to ``end``.
        """
        clauses, params = period_bounds("received_at", start, end)
        return self.count(f"SELECT COUNT(*) FROM snort_alerts {clauses}", params)

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

    def count_detections_by_severity(
        self, since: datetime | None = None, end: datetime | None = None,
        *, include_snort: bool = True,
    ) -> dict[str, int]:
        """Severity counts across *both* detection sources.

        The dashboard and the IDS summary describe the same thing to an
        operator - "how much did the system detect, and how bad" - so they must
        count the same records. Counting Snort alerts alone made the dashboard
        report a subset of what the IDS screen listed, and the two disagreed by
        exactly the detections AETHRA-SEC had raised itself.

        Each source is filtered on its own arrival column: ``received_at`` for
        an ingested Snort alert, ``created_at`` for a detection this system
        raised. Both mean "when this became known", which is what a time window
        on a dashboard asks about.
        """
        counts: dict[str, int] = {}
        queries = [("traffic_anomalies", "created_at")]
        if include_snort:
            queries.insert(0, ("snort_alerts", "received_at"))
        for table, column in queries:
            clauses, params = period_bounds(column, since, end)
            rows = self.db.query(
                f"SELECT severity, COUNT(*) AS c FROM {table} {clauses} "
                "GROUP BY severity",
                params,
            )
            for row in rows:
                key = as_text(row["severity"]).upper()
                counts[key] = counts.get(key, 0) + (as_int(row["c"]) or 0)
        return counts

    def count_by_severity(
        self, since: datetime | None = None, end: datetime | None = None
    ) -> dict[str, int]:
        """Snort alert counts grouped by severity, this source alone.

        Kept for callers that genuinely mean Snort's own queue. Anything
        describing "detections" wants
        :meth:`count_detections_by_severity` instead.
        """
        clauses, params = period_bounds("received_at", since, end)
        rows = self.db.query(
            f"SELECT severity, COUNT(*) AS c FROM snort_alerts {clauses} "
            "GROUP BY severity",
            params,
        )
        return {as_text(r["severity"]): as_int(r["c"]) or 0 for r in rows}

    def detections_per_interval(
        self, start: datetime | None, end: datetime, minutes: int = 5,
        *, include_snort: bool = True,
    ) -> list[tuple[datetime, int]]:
        """Detection counts bucketed into fixed intervals for the IDS chart.

        Counts *both* detection sources, on the same half-open bounds as
        :meth:`count_detections_by_severity`, so the chart, the severity donut
        and the headline figure are three views of one dataset rather than
        three numbers that can disagree.
        """
        bucket = max(1, min(int(minutes), 1440)) * 60
        totals: dict[datetime, int] = {}
        sources = [("traffic_anomalies", "created_at")]
        if include_snort:
            sources.insert(0, ("snort_alerts", "received_at"))
        for table, column in sources:
            clauses, bounds = period_bounds(column, start, end)
            rows = self.db.query(
                f"SELECT FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP({column}) / %s) * %s) "
                f"AS bucket, COUNT(*) AS c FROM {table} {clauses} "
                "GROUP BY bucket ORDER BY bucket ASC LIMIT 2000",
                [bucket, bucket, *bounds],
            )
            for row in rows:
                stamp = as_dt(row["bucket"])
                if stamp:
                    totals[stamp] = totals.get(stamp, 0) + (as_int(row["c"]) or 0)
        return sorted(totals.items())

    def last_alert_time(self) -> datetime | None:
        """Timestamp of the most recently received alert."""
        return as_dt(self.db.query_value("SELECT MAX(received_at) FROM snort_alerts"))

    def mark_all_reviewed(self, user_id: int | None) -> int:
        """Move every alert still in NEW to REVIEWED.

        Counts and updates exactly the rows the sidebar badge counts, so the
        badge cannot survive the action that is supposed to clear it. Alerts an
        analyst has already put into another state - acknowledged, escalated,
        suppressed - are left alone: those are decisions, and a bulk action
        must not quietly overwrite them.

        Returns:
            How many alerts moved.
        """
        return self.db.execute(
            "UPDATE snort_alerts SET status = %s, evaluated_by = %s, "
            "evaluated_at = %s WHERE status = %s",
            (str(AlertStatus.REVIEWED), user_id, to_db(utcnow()), str(AlertStatus.NEW)),
        )

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

    def mean_detection_latency(
        self, since: datetime | None, end: datetime | None = None
    ) -> float | None:
        """Mean seconds between Snort's event time and our ingest time.

        Only rows where Snort supplied its own timestamp are included, so the
        measurement never rests on an invented value (§81).
        """
        clauses, params = period_bounds(
            "received_at", since, end, "alert_time IS NOT NULL"
        )
        value = self.db.query_value(
            "SELECT AVG(TIMESTAMPDIFF(MICROSECOND, alert_time, received_at)) "
            f"FROM snort_alerts {clauses}",
            params,
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
        self,
        dedup_key_parts: tuple[str, str, str, int | None],
        since: datetime,
        until: datetime | None = None,
    ) -> TrafficAnomaly | None:
        """Find the episode an observation at ``until`` belongs to (§92).

        ``since`` bounds the episode's last observation from below; ``until``,
        when given, requires the episode to have started no later than the
        observation, so an observation is never folded into a LATER episode.
        """
        rule_id, src_ip, dst_ip, dst_port = dedup_key_parts
        clauses = ["rule_id = %s", "src_ip = %s", "dst_ip = %s", "last_seen >= %s"]
        params: list[Any] = [rule_id, src_ip, dst_ip, to_db(since)]
        if until is not None:
            clauses.append("first_seen <= %s")
            params.append(to_db(until))
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

    def merge_scan_evidence(
        self, anomaly_id: int, target: str, ports: list[Any] | None
    ) -> None:
        """Add one target, and the ports its detection saw, to a scan episode.

        A port-scan episode is one scanning source across the targets it
        probed while active. Each target's detection reports the ports its
        window saw (``ports_sample``, at most 40); their union is kept as
        ``ports_observed``. It is a lower bound - the rule reports ports only
        when it fires - and is labelled so wherever it is shown. Called only
        from the capture worker, which is the only writer of detection rows.
        """
        row = self.db.query_one(
            "SELECT evidence, dst_ip FROM traffic_anomalies WHERE id = %s", (anomaly_id,)
        )
        if not row:
            return
        evidence = decode_json(row.get("evidence")) or {}
        targets = list(evidence.get("scan_targets") or [as_text(row.get("dst_ip"))])
        if target and target not in targets and len(targets) < 1024:
            targets.append(target)
        observed = set(evidence.get("ports_observed") or evidence.get("ports_sample") or [])
        for port in ports or []:
            if len(observed) >= 4096:
                break
            observed.add(port)
        evidence["scan_targets"] = targets
        evidence["scan_target_count"] = len(targets)
        evidence["ports_observed"] = sorted(observed, key=lambda p: (str(type(p)), p))
        evidence["ports_observed_note"] = (
            "Ports reported by this scan's detections; a lower bound on the "
            "ports probed."
        )
        self.db.execute(
            "UPDATE traffic_anomalies SET evidence = %s WHERE id = %s",
            (encode_json(evidence), anomaly_id),
        )

    def anomaly_with_start(
        self, dedup_key_parts: tuple[str, str, str, int | None], first_seen: datetime
    ) -> TrafficAnomaly | None:
        """An episode already stored for exactly this key and packet-clock start.

        Makes recording an episode idempotent: the same detection processed
        twice finds the row it already wrote instead of writing another.
        """
        rule_id, src_ip, dst_ip, dst_port = dedup_key_parts
        port_clause = "dst_port IS NULL" if dst_port is None else "dst_port = %s"
        params: list[Any] = [rule_id, src_ip, dst_ip, to_db(first_seen)]
        if dst_port is not None:
            params.append(dst_port)
        row = self.db.query_one(
            f"{_ANOMALY_SELECT} WHERE rule_id = %s AND src_ip = %s AND dst_ip = %s "
            f"AND first_seen = %s AND {port_clause} LIMIT 1",
            tuple(params),
        )
        return self._map_anomaly(row) if row else None

    def recent_anomaly_for_source(
        self, rule_id: str, src_ip: str, since: datetime,
        until: datetime | None = None,
    ) -> TrafficAnomaly | None:
        """The running episode of ``rule_id`` from ``src_ip``, any destination.

        For rules that measure a source across targets (ICMP, TCP SYN), so a
        measurement whose most recent destination changed still extends the
        source's episode instead of being lost.
        """
        row = self.db.query_one(
            f"{_ANOMALY_SELECT} WHERE rule_id = %s AND src_ip = %s "
            "AND last_seen >= %s AND (%s IS NULL OR first_seen <= %s) "
            "ORDER BY last_seen DESC LIMIT 1",
            (rule_id, src_ip, to_db(since), to_db(until) if until else None,
             to_db(until) if until else None),
        )
        return self._map_anomaly(row) if row else None

    def insert_anomaly(self, anomaly: TrafficAnomaly) -> int:
        """Insert one deterministic traffic anomaly."""
        now = utcnow()
        return self.db.insert(
            "INSERT INTO traffic_anomalies (rule_id, category, title, "
            "observation, why_it_matters, what_to_check, severity, confidence, "
            "src_ip, dst_ip, dst_port, protocol, interface, observed_value, "
            "threshold_value, window_seconds, event_count, detected_at, first_seen, "
            "last_seen, evidence, host_id, evaluation, source, created_at, "
            "latest_value, latest_measured_at, peak_severity) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                anomaly.rule_id[:48], str(anomaly.category), anomaly.title[:190],
                anomaly.observation, anomaly.why_it_matters,
                anomaly.what_to_check, str(anomaly.severity),
                max(0, min(100, anomaly.confidence)), anomaly.src_ip[:45],
                anomaly.dst_ip[:45], anomaly.dst_port, anomaly.protocol[:16],
                anomaly.interface[:96], round(anomaly.observed_value, 3),
                round(anomaly.threshold_value, 3), anomaly.window_seconds,
                anomaly.event_count, to_db(anomaly.detected_at),
                to_db(anomaly.first_seen or now),
                to_db(anomaly.last_seen or now), encode_json(anomaly.evidence),
                anomaly.host_id, str(anomaly.evaluation), str(anomaly.source),
                to_db(anomaly.created_at or now),
                # A first sighting's latest measurement is the one that
                # raised it, and its peak is the severity it was raised with.
                round(anomaly.observed_value, 3),
                # The packet clock: the triggering packet's capture time, as
                # every later measurement now records too. detected_at is the
                # analysis clock and stays in its own column.
                to_db(anomaly.last_seen or anomaly.detected_at or now),
                str(anomaly.severity),
            ),
        )

    def raise_anomaly_pps(self, anomaly_id: int, packets_per_second: float) -> None:
        """Raise an episode's recorded pps to ``packets_per_second`` if higher.

        A port scan or host sweep is graded on the pps legend from the rate in
        ``evidence.packets_per_second``. When a repeat observation of the same
        episode measures faster, its severity rises (see
        :meth:`update_anomaly_occurrence`) and the recorded pps must rise with
        it, or the Rate column would show a figure lower than the one the
        severity was graded on. It never falls, for the same reason the peak
        severity never falls. A single statement, so concurrent folds cannot
        lower it.
        """
        self.db.execute(
            "UPDATE traffic_anomalies SET evidence = JSON_SET("
            "COALESCE(NULLIF(evidence, ''), '{}'), '$.packets_per_second', "
            "GREATEST(COALESCE(CAST(JSON_VALUE(NULLIF(evidence, ''), "
            "'$.packets_per_second') AS DECIMAL(14,1)), 0), %s)) "
            "WHERE id = %s",
            (round(float(packets_per_second), 1), anomaly_id),
        )

    def record_episode_measurement(
        self,
        anomaly_id: int,
        measurement: dict[str, Any],
        rate: float,
    ) -> None:
        """Store the facts of a repeat measurement inside the episode's evidence.

        ``evidence.latest_measurement`` is always replaced; the same object
        goes to ``evidence.peak_measurement`` only when ``rate`` exceeds the
        peak already stored in ``observed_value``. Call it BEFORE
        :meth:`update_anomaly_occurrence`, which raises that peak.

        Until this existed a repeat measurement updated the rate columns and
        nothing else: the observation sentence and every evidence field stayed
        as they were at the instant the threshold was first crossed. Detection
        2860 therefore showed a latest and peak rate of 1,040.2 pps beside an
        observation of "600 packets in 5 s (120.0 packets/second) ... Low", and
        detection 2817 showed 299 / 330.2 pps beside the same 120 pps
        sentence. The trigger evidence is kept unchanged - it is a true record
        of the threshold crossing - and the later measurements are stored
        beside it, each with its own time, counts and capture state.

        One statement, so the peak comparison and the write cannot interleave
        with another fold. The conditional path keeps the value a JSON object:
        MariaDB 10.4 turns ``IF(cond, JSON_QUERY(...), ...)`` into a quoted
        string, whereas choosing the PATH conditionally does not.
        """
        document = json.dumps(measurement, default=str)
        self.db.execute(
            "UPDATE traffic_anomalies SET evidence = JSON_REMOVE(JSON_SET("
            "JSON_SET(COALESCE(NULLIF(evidence, ''), '{}'), "
            "'$.latest_measurement', JSON_QUERY(%s, '$')), "
            "IF(%s > COALESCE(observed_value, 0), '$.peak_measurement', "
            "'$.discarded_measurement'), JSON_QUERY(%s, '$')), "
            "'$.discarded_measurement') "
            "WHERE id = %s",
            (document, round(float(rate), 3), document, anomaly_id),
        )

    def update_anomaly_occurrence(
        self,
        anomaly_id: int,
        *,
        last_seen: datetime,
        observed_value: float,
        severity: "Severity | None" = None,
        measured_at: datetime | None = None,
    ) -> None:
        """Fold a repeat observation into an existing anomaly record.

        Args:
            observed_value: this observation's measurement. It becomes
                ``latest_value``, and raises ``observed_value`` only when it
                exceeds the peak already stored.
            severity: the classification this measurement produces. When given
                it raises ``severity`` if it is higher - which is what makes an
                escalation
                visible to the table, the counters and the filters at once -
                and raises ``peak_severity`` only when it is higher than the
                peak already recorded, so the peak never falls. ``None``
                leaves both alone, which is correct for a rule whose severity
                does not come from a packet rate.

        The whole fold is a single statement. Two capture threads folding the
        same episode cannot interleave a read with a write and lose an
        observation, and the peak cannot be lowered by a slower thread
        writing a stale value.
        """
        if severity is None:
            self.db.execute(
                "UPDATE traffic_anomalies SET event_count = event_count + 1, "
                "last_seen = %s, latest_value = %s, latest_measured_at = %s, "
                "observed_value = GREATEST(observed_value, %s) "
                "WHERE id = %s",
                (
                    to_db(last_seen), round(observed_value, 3),
                    to_db(measured_at or last_seen),
                    round(observed_value, 3), anomaly_id,
                ),
            )
            return
        # FIELD() gives the severity ladder a numeric order inside SQL, so both
        # the severity and the peak are raised in the statement that writes the
        # current measurement.
        #
        # ``severity`` is raised, never lowered. It used to be replaced
        # outright, which meant an episode that reached 1,733 pps reported LOW
        # as soon as the rate tailed off below 500 - and this column is what
        # the IDS badge, the severity counters, the filter, exports, the
        # dashboard and notification eligibility all read. An attack's
        # severity is the worst it has validly measured, not whatever it
        # happened to be doing at the last sample.
        #
        # The live rate is still here in full: ``latest_value`` and
        # ``latest_measured_at`` carry the current measurement, so a falling
        # rate remains visible without rewriting what the attack reached.
        ladder = "'INFO','LOW','MEDIUM','HIGH','CRITICAL'"
        rise = (
            "IF(FIELD(%s, " + ladder + ") > "
            "FIELD(COALESCE({column}, %s), " + ladder + "), %s, "
            "COALESCE({column}, %s))"
        )
        self.db.execute(
            "UPDATE traffic_anomalies SET event_count = event_count + 1, "
            "last_seen = %s, latest_value = %s, latest_measured_at = %s, "
            "observed_value = GREATEST(observed_value, %s), "
            "severity = " + rise.format(column="severity") + ", "
            "peak_severity = " + rise.format(column="peak_severity") + " "
            "WHERE id = %s",
            (
                to_db(last_seen), round(observed_value, 3),
                to_db(measured_at or last_seen),
                round(observed_value, 3),
                # severity: compare, then keep whichever is higher
                str(severity), "", str(severity), str(severity),
                # peak_severity: the same, against its own column
                str(severity), "", str(severity), str(severity),
                anomaly_id,
            ),
        )

    def record_severity_transition(
        self,
        anomaly_id: int,
        *,
        occurred_at: datetime,
        previous: "Severity",
        new: "Severity",
        observed_value: float | None = None,
        window_seconds: int | None = None,
        measured_at: datetime | None = None,
    ) -> int:
        """Log one actual change of classification.

        Called only when the classification really changed. A measurement
        that leaves severity where it was writes nothing, so this table holds
        transitions rather than observations and cannot be inflated by a
        steady flood.
        """
        return self.db.insert(
            "INSERT INTO anomaly_severity_transitions (anomaly_id, "
            "occurred_at, previous_severity, new_severity, observed_value, "
            "window_seconds, measured_at, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                anomaly_id, to_db(occurred_at), str(previous), str(new),
                None if observed_value is None else round(observed_value, 3),
                window_seconds, to_db(measured_at), to_db(utcnow()),
            ),
        )

    def severity_transitions(self, anomaly_id: int) -> list[dict[str, Any]]:
        """Every recorded change for one episode, oldest first."""
        return self.db.query(
            "SELECT id, occurred_at, previous_severity, new_severity, "
            "observed_value, window_seconds, measured_at "
            "FROM anomaly_severity_transitions WHERE anomaly_id = %s "
            "ORDER BY occurred_at ASC, id ASC",
            (anomaly_id,),
        )

    def get_anomaly(self, anomaly_id: int) -> TrafficAnomaly | None:
        """Fetch one anomaly."""
        row = self.db.query_one(f"{_ANOMALY_SELECT} WHERE id = %s", (anomaly_id,))
        return self._map_anomaly(row) if row else None

    @staticmethod
    def _anomaly_filter(
        *,
        text: str = "",
        severity: str = "",
        category: str = "",
        src_ip: str = "",
        rule_id: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> QueryFilter:
        """The WHERE clause for an anomaly search. See :meth:`_alert_filter`."""
        query = QueryFilter(_ANOMALY_FILTERABLE)
        query.equals("severity", severity)
        query.equals("category", category)
        query.equals("src_ip", src_ip)
        query.equals("rule_id", rule_id)
        query.gte("created_at", to_db(start))
        query.lt("created_at", to_db(end))
        query.any_of(("title", "observation", "src_ip", "dst_ip"), text)
        return query

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
        query = self._anomaly_filter(
            text=text, severity=severity, category=category, src_ip=src_ip,
            rule_id=rule_id, start=start, end=end,
        )
        order = order_clause(sort_by, sort_dir, _ANOMALY_SORTABLE, "created_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_ANOMALY_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map_anomaly)

    def detection_totals(
        self, *, alert_filters: dict[str, Any], anomaly_filters: dict[str, Any]
    ) -> dict[str, int]:
        """Severity totals for both sources over the filters given.

        Counted in the database, over the same predicate that selects the rows
        and with no row limit, so the summary above a table describes every
        matching detection rather than the page of them that fitted.

        Returns:
            Severity name to count, plus ``total`` - the sum, so a caller can
            never present a total that disagrees with its own parts.
        """
        counts: dict[str, int] = {}
        for builder, filters in (
            (self._alert_filter, alert_filters),
            (self._anomaly_filter, anomaly_filters),
        ):
            if filters is None:
                continue
            query = builder(**filters)
            table = (
                "snort_alerts" if builder is self._alert_filter
                else "traffic_anomalies"
            )
            rows = self.db.query(
                f"SELECT severity, COUNT(*) AS c FROM {table} "
                f"{query.where_clause()} GROUP BY severity",
                query.bound_params(),
            )
            for row in rows:
                key = as_text(row["severity"]).upper()
                counts[key] = counts.get(key, 0) + (as_int(row["c"]) or 0)
        counts["total"] = sum(v for k, v in counts.items() if k != "total")
        return counts

    def count_unreviewed_matching(
        self, *, alert_filters: dict[str, Any], anomaly_filters: dict[str, Any]
    ) -> int:
        """Untriaged detections across both sources, over the same filters."""
        total = 0
        if alert_filters is not None:
            query = self._alert_filter(**alert_filters)
            query.equals("status", str(AlertStatus.NEW))
            total += self.count(
                f"SELECT COUNT(*) FROM snort_alerts {query.where_clause()}",
                query.bound_params(),
            )
        if anomaly_filters is not None:
            query = self._anomaly_filter(**anomaly_filters)
            query.is_null("reviewed_at")
            query.raw(
                "(evaluation IS NULL OR evaluation = '' OR evaluation = %s)",
                str(EvaluationLabel.UNCLASSIFIED),
            )
            total += self.count(
                f"SELECT COUNT(*) FROM traffic_anomalies {query.where_clause()}",
                query.bound_params(),
            )
        return total

    def mark_all_anomalies_reviewed(self, user_id: int | None) -> int:
        """Stamp every unreviewed anomaly as read by ``user_id``.

        Writes the read receipt only. ``evaluation`` is deliberately not
        touched: those labels are an analyst's verdict and the input to the
        detection-accuracy statistics, so a bulk action must never assign one.

        Returns:
            How many anomalies this call marked.
        """
        return self.db.execute(
            "UPDATE traffic_anomalies SET reviewed_at = %s, reviewed_by = %s "
            "WHERE reviewed_at IS NULL",
            (to_db(utcnow()), user_id),
        )

    def mark_anomaly_reviewed(self, anomaly_id: int, user_id: int | None) -> bool:
        """Stamp one anomaly as read by ``user_id``.

        The same receipt the bulk action writes, with the same restraint: no
        ``evaluation`` label is assigned, and an anomaly already reviewed keeps
        the reviewer who saw it first rather than being rewritten by whoever
        opened it next.

        Returns:
            True when this call was the one that marked it.
        """
        return bool(
            self.db.execute(
                "UPDATE traffic_anomalies SET reviewed_at = %s, reviewed_by = %s "
                "WHERE id = %s AND reviewed_at IS NULL",
                (to_db(utcnow()), user_id, anomaly_id),
            )
        )

    def set_anomaly_evaluation(
        self, anomaly_id: int, evaluation: EvaluationLabel, user_id: int | None
    ) -> bool:
        """Record an analyst's verdict on one of AETHRA-SEC's own detections.

        ``traffic_anomalies.evaluation`` has always existed and nothing ever
        wrote it, so a verdict could be recorded for a Snort alert and not for
        a detection this system raised itself. On an installation where Snort
        is quiet that made the detection-accuracy statistics unanswerable: the
        labels they are computed from could only be applied to a small minority
        of the detections.

        Classifying also stamps the read receipt, because forming a judgement
        necessarily means having read it - but only when the receipt is still
        empty, so the analyst who saw it first keeps the credit.

        The verdict is stored *alongside* the detection, never over it. The
        rule id, observed value, threshold and evidence are untouched, so an
        anomaly classified FALSE_POSITIVE remains traceable to the rule that
        raised it and the measurement that triggered it.

        Returns:
            True when a row was updated.
        """
        changed = self.db.execute(
            "UPDATE traffic_anomalies SET evaluation = %s WHERE id = %s",
            (str(evaluation), anomaly_id),
        )
        if changed:
            self.db.execute(
                "UPDATE traffic_anomalies SET reviewed_at = %s, reviewed_by = %s "
                "WHERE id = %s AND reviewed_at IS NULL",
                (to_db(utcnow()), user_id, anomaly_id),
            )
        return bool(changed)

    # ------------------------------------------------------------------
    # Attack statistics (one GROUP BY per source; never a row scan in Python)
    # ------------------------------------------------------------------
    def aethra_episode_statistics(
        self, start: datetime | None, end: datetime | None, active_since: datetime
    ) -> list[dict[str, Any]]:
        """Per AETHRA-SEC rule: episodes started in ``[start, end)``.

        One detection record is one episode (see ATTACK_EPISODE_LIFECYCLE.md),
        so episodes are counted as rows. ``correlated`` counts episodes whose
        correlated attack also holds at least one Snort alert - a link the
        correlation engine established, not a timestamp coincidence.
        ``revised`` counts rows written under the 15 Oct 2026 episode rules
        (``measurement_clock: packet``); older rows may hold merged runs or
        reply-direction duplicates, and the page says so.
        """
        clauses, params = period_bounds("a.first_seen", start, end)
        rows = self.db.query(
            "SELECT a.rule_id, COUNT(*) AS episodes, "
            "SUM(a.last_seen >= %s) AS active, "
            "SUM(a.incident_id IS NOT NULL AND EXISTS (SELECT 1 FROM snort_alerts s "
            "    WHERE s.incident_id = a.incident_id)) AS correlated, "
            "SUM(COALESCE(JSON_VALUE(NULLIF(a.evidence, ''), '$.measurement_clock') "
            "    = 'packet', 0)) AS revised, "
            "MAX(a.first_seen) AS latest "
            f"FROM traffic_anomalies a {clauses} GROUP BY a.rule_id",
            [to_db(active_since), *params],
        )
        return [
            {
                "rule_id": as_text(r["rule_id"]),
                "episodes": as_int(r["episodes"]) or 0,
                "active": as_int(r["active"]) or 0,
                "correlated": as_int(r["correlated"]) or 0,
                "revised": as_int(r["revised"]) or 0,
                "latest": r["latest"],
            }
            for r in rows
        ]

    def snort_signature_statistics(
        self, start: datetime | None, end: datetime | None
    ) -> list[dict[str, Any]]:
        """Per Snort (generator, signature, revision): records and raw alerts.

        ``records`` are stored rows; ``raw_alerts`` adds every repeat folded
        into them (``duplicate_count``), i.e. the alert lines Snort wrote. A
        repeat is attributed to its row's start time, so a period boundary
        that falls inside a long episode counts all its repeats in the period
        the episode began - stated on the page.
        """
        clauses, params = period_bounds("COALESCE(alert_time, received_at)", start, end)
        rows = self.db.query(
            "SELECT generator_id, signature_id, revision, COUNT(*) AS records, "
            "SUM(duplicate_count) AS raw_alerts, "
            "MAX(COALESCE(last_alert_time, alert_time, received_at)) AS latest "
            f"FROM snort_alerts {clauses} "
            "GROUP BY generator_id, signature_id, revision",
            params,
        )
        return [
            {
                "generator_id": as_int(r["generator_id"]),
                "signature_id": as_int(r["signature_id"]),
                "revision": as_int(r["revision"]),
                "records": as_int(r["records"]) or 0,
                "raw_alerts": as_int(r["raw_alerts"]) or 0,
                "latest": r["latest"],
            }
            for r in rows
        ]

    def snort_evidence_for_incident(self, incident_id: int, limit: int = 200) -> list[SnortAlert]:
        """Snort alerts linked to one correlated attack, newest first, bounded."""
        rows = self.db.query(
            f"{_ALERT_SELECT} WHERE incident_id = %s "
            "ORDER BY COALESCE(alert_time, received_at) DESC LIMIT %s",
            (incident_id, max(1, min(int(limit), 1000))),
        )
        return self._map_all(rows, self._map_alert)

    def count_unreviewed_anomalies(self) -> int:
        """Anomalies no analyst has evaluated yet.

        Mirrors the unresolved-alert counter so the Alerts screen can report
        both sources with one meaning of "still needs a look".
        """
        # Unreviewed means neither read nor judged. Counting only the
        # evaluation left the counter unclearable without fabricating a
        # verdict; counting only the receipt would have called a detection an
        # analyst had already classified "unreviewed".
        return self.count(
            "SELECT COUNT(*) FROM traffic_anomalies "
            "WHERE reviewed_at IS NULL "
            "AND (evaluation IS NULL OR evaluation = '' OR evaluation = %s)",
            (str(EvaluationLabel.UNCLASSIFIED),),
        )

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

    def count_anomalies_in_period(
        self, start: datetime | None, end: datetime | None = None
    ) -> int:
        """Anomalies recorded inside ``[start, end)``."""
        clauses, params = period_bounds("created_at", start, end)
        return self.count(f"SELECT COUNT(*) FROM traffic_anomalies {clauses}", params)

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
