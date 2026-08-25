"""Dashboard data assembly (§9, §63, §72, §113).

Every widget value comes from a stored record or a live in-memory counter. On a
freshly installed system every figure is genuinely zero, and
:attr:`DashboardSnapshot.has_any_data` lets the interface say "No data
available" instead of drawing an empty chart that looks broken.

Queries are narrow and indexed; the dashboard refreshes from live events and
only re-queries the counters that cannot be derived incrementally (§113).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import to_local, utcnow

LOGGER = get_logger("services.dashboard")


class DashboardService:
    """Assembles the dashboard snapshot from real stored data."""

    def __init__(
        self,
        traffic: TrafficRepository,
        alerts: AlertRepository,
        incidents: IncidentRepository,
        scans: ScanRepository,
        hosts: HostRepository,
        audit: AuditRepository,
        access: AccessControl,
    ) -> None:
        """Bind the service to the repositories it reads."""
        self._traffic = traffic
        self._alerts = alerts
        self._incidents = incidents
        self._scans = scans
        self._hosts = hosts
        self._audit = audit
        self._access = access

    @staticmethod
    def _local_day_start() -> datetime:
        """UTC instant corresponding to local midnight today.

        "Packets today" means the operator's today, so the boundary is computed
        in local time and converted back to UTC for the query (§80).
        """
        local_now = to_local(utcnow())
        assert local_now is not None
        midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight.astimezone(utcnow().tzinfo)

    def snapshot(
        self, session: Session, *, window_hours: float = 24.0, chart_points: int = 60
    ) -> DashboardSnapshot:
        """Build the dashboard view over the requested window.

        Each figure is fetched independently and a failure in one does not
        blank the whole dashboard - it leaves that counter at zero while the
        System Health screen reports the underlying problem.

        ``window_hours`` is a float so the interface can offer sub-hour windows
        (a 15-minute view during an active incident) as well as days; it is
        floored at three minutes, below which the stored aggregates have
        nothing to say.
        """
        self._access.require(session, Permission.DASHBOARD_VIEW)

        now = utcnow()
        window_start = now - timedelta(hours=max(0.05, float(window_hours)))
        day_start = self._local_day_start()
        snapshot = DashboardSnapshot(generated_at=now)

        def attempt(name: str, action: Any) -> Any:
            """Run one query, logging and swallowing its failure."""
            try:
                return action()
            except Exception:  # noqa: BLE001
                LOGGER.debug("Dashboard query '%s' failed.", name, exc_info=True)
                return None

        snapshot.packets_today = attempt(
            "packets_today", lambda: self._traffic.packets_today(day_start)
        ) or 0
        snapshot.total_packets_stored = attempt(
            "total_packets", self._traffic.total_packets_observed
        ) or 0
        snapshot.last_packet_at = attempt("last_packet", self._traffic.last_packet_time)

        # The trend arrows compare today with the equivalent span of the
        # previous day, and are computed only when the database actually holds
        # aggregates reaching back that far.
        previous_start = day_start - timedelta(days=1)
        earliest_aggregate = attempt(
            "earliest_aggregate", self._traffic.earliest_aggregate_time
        )
        if earliest_aggregate is not None and earliest_aggregate <= previous_start:
            snapshot.packets_previous_period = attempt(
                "packets_previous",
                lambda: self._traffic.packets_between(previous_start, day_start),
            )

        snapshot.observed_hosts = attempt("hosts_total", self._hosts.count_all) or 0
        snapshot.active_hosts = attempt(
            "hosts_active", lambda: self._hosts.count_active_since(window_start)
        ) or 0

        snapshot.open_ports = attempt("open_ports", self._scans.count_open_ports) or 0
        snapshot.scans_total = attempt("scans_total", self._scans.count_scans) or 0
        snapshot.last_scan_at = attempt("last_scan", self._scans.last_scan_time)
        snapshot.open_findings = attempt(
            "open_findings", self._scans.count_open_findings
        ) or 0
        findings_by_risk = attempt(
            "findings_by_risk", self._scans.count_findings_by_risk
        ) or {}
        snapshot.critical_findings = int(findings_by_risk.get("CRITICAL", 0))
        snapshot.high_findings = int(findings_by_risk.get("HIGH", 0))

        snapshot.ids_alerts_today = attempt(
            "alerts_today", lambda: self._alerts.count_alerts_since(day_start)
        ) or 0
        snapshot.ids_alerts_total = attempt("alerts_total", self._alerts.count_alerts) or 0
        snapshot.last_alert_at = attempt("last_alert", self._alerts.last_alert_time)
        earliest_alert = attempt("earliest_alert", self._alerts.earliest_alert_time)
        if earliest_alert is not None and earliest_alert <= previous_start:
            snapshot.alerts_previous_period = attempt(
                "alerts_previous",
                lambda: self._alerts.count_alerts_between(previous_start, day_start),
            )
        severity = attempt(
            "alerts_by_severity", lambda: self._alerts.count_by_severity(window_start)
        ) or {}
        snapshot.critical_alerts = int(severity.get("CRITICAL", 0))
        snapshot.high_alerts = int(severity.get("HIGH", 0))
        snapshot.medium_alerts = int(severity.get("MEDIUM", 0))
        snapshot.low_alerts = int(severity.get("LOW", 0))
        snapshot.info_alerts = int(severity.get("INFO", 0))
        snapshot.severity_distribution = tuple(sorted(severity.items()))

        snapshot.anomalies_today = attempt(
            "anomalies_today", lambda: self._alerts.count_anomalies_since(day_start)
        ) or 0
        snapshot.open_incidents = attempt("incidents_open", self._incidents.count_open) or 0
        snapshot.mean_detection_latency_seconds = attempt(
            "latency", lambda: self._alerts.mean_detection_latency(window_start)
        )

        aggregates = attempt(
            "traffic_series",
            lambda: self._traffic.aggregates_between(window_start, now),
        ) or []
        snapshot.traffic_series = self._downsample_traffic(aggregates, chart_points)

        snapshot.alert_series = tuple(
            attempt(
                "alert_series",
                lambda: self._alerts.alerts_per_interval(window_start, now, minutes=15),
            )
            or ()
        )
        protocols = attempt(
            "protocols", lambda: self._traffic.protocol_distribution(window_start)
        ) or []
        snapshot.protocol_distribution = tuple(
            (p.protocol, p.packets) for p in protocols
        )

        snapshot.recent_alerts = tuple(
            attempt("recent_alerts", lambda: self._alerts.recent_alerts(8)) or ()
        )
        snapshot.recent_findings = tuple(
            attempt(
                "recent_findings",
                lambda: self._scans.search_findings(unresolved_only=True, limit=8),
            )
            or ()
        )
        snapshot.recent_incidents = tuple(
            attempt("recent_incidents", lambda: self._incidents.recent(8)) or ()
        )
        snapshot.recent_activity = tuple(
            attempt("recent_activity", lambda: self._audit.recent_activity(8)) or ()
        )
        snapshot.threat_timeline = tuple(
            attempt("timeline", lambda: self._incidents.timeline(window_start, 30)) or ()
        )
        return snapshot

    @staticmethod
    def _downsample_traffic(
        aggregates: list[Any], points: int
    ) -> tuple[tuple[datetime, float], ...]:
        """Downsample stored aggregates into chart points (§106).

        Averaging within each bucket keeps the series honest: it never invents
        points for intervals that produced no aggregate.
        """
        if not aggregates:
            return ()
        target = max(10, points)
        if len(aggregates) <= target:
            return tuple(
                (a.interval_start, float(a.packets_per_second)) for a in aggregates
            )
        group = max(1, len(aggregates) // target)
        series: list[tuple[datetime, float]] = []
        for index in range(0, len(aggregates), group):
            chunk = aggregates[index : index + group]
            mean = sum(float(a.packets_per_second) for a in chunk) / len(chunk)
            series.append((chunk[0].interval_start, mean))
        return tuple(series)

    def network_overview(
        self, session: Session, window_hours: float = 24.0
    ) -> dict[str, Any]:
        """Network overview figures for the dashboard's network card."""
        self._access.require(session, Permission.DASHBOARD_VIEW)
        since = utcnow() - timedelta(hours=max(0.05, float(window_hours)))
        try:
            return {
                "top_sources": self._traffic.top_sources(since, 5),
                "top_destinations": self._traffic.top_destinations(since, 5),
                "top_ports": self._traffic.top_ports(since, 5),
                "protocols": self._traffic.protocol_distribution(since),
                "interfaces": self._traffic.distinct_interfaces(),
            }
        except Exception:  # noqa: BLE001
            LOGGER.debug("Network overview query failed.", exc_info=True)
            return {
                "top_sources": [], "top_destinations": [], "top_ports": [],
                "protocols": [], "interfaces": [],
            }
