"""Dashboard data assembly (§9, §63, §72, §113, §114).

Every widget value comes from a stored record or a live in-memory counter. On a
freshly installed system every figure is genuinely zero, and
:attr:`DashboardSnapshot.has_any_data` lets the interface say "No data
available" instead of drawing an empty chart that looks broken.

One filter, two kinds of figure
-------------------------------
The page is assembled from a single :class:`~aethra_sec.models.periods.
DashboardPeriod`. Every period-scoped query in this module is given that same
half-open ``[start, end)`` pair, so no two widgets can end up describing
different spans - the severity donut and the headline detection count are
literally the same query, one grouped and one summed.

Current-state figures - open findings, hosts in inventory - are
deliberately *not* given the period. A backlog does not shrink because a new
day began, and reporting it as zero at 00:00 would be a false all-clear.

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
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.models.periods import DashboardPeriod
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.dashboard")

#: How far back "active hosts" looks. This is a *recency* question about the
#: present - "what is on the network now" - not a daily total, so it keeps its
#: own trailing window and is unaffected by the reporting period or by
#: midnight. Zeroing it at 00:00 would claim the network had emptied.
ACTIVE_HOST_RECENCY_HOURS = 24.0


class DashboardService:
    """Assembles the dashboard snapshot from real stored data."""

    #: How long the expensive top-sources panel is cached (seconds).
    OVERVIEW_TTL_SECONDS = 15.0

    def __init__(
        self,
        traffic: TrafficRepository,
        alerts: AlertRepository,
        scans: ScanRepository,
        hosts: HostRepository,
        audit: AuditRepository,
        access: AccessControl,
    ) -> None:
        """Bind the service to the repositories it reads."""
        self._traffic = traffic
        self._alerts = alerts
        self._scans = scans
        self._hosts = hosts
        self._audit = audit
        self._access = access
        #: (key, monotonic_stamp, result) for the top-sources panel.
        self._overview_cache: tuple[Any, float, dict[str, Any]] | None = None

    def snapshot(
        self,
        session: Session,
        *,
        period: DashboardPeriod | None = None,
        chart_points: int = 60,
    ) -> DashboardSnapshot:
        """Build the dashboard view over one reporting period.

        Args:
            session: the requesting session; needs ``dashboard.view``.
            period: the reporting window. Defaults to today, from local
                midnight to the present moment.
            chart_points: target number of points in the traffic series.

        Each figure is fetched independently and a failure in one does not
        blank the whole dashboard - it leaves that counter at zero while the
        System Health screen reports the underlying problem.

        This method only ever reads. Changing the period changes which rows are
        selected and nothing else: no record is written, moved or deleted when
        the day rolls over.
        """
        self._access.require(session, Permission.DASHBOARD_VIEW)

        window = (period or DashboardPeriod.default()).refreshed()
        start, end = window.start, window.end
        snapshot = DashboardSnapshot(
            generated_at=utcnow(),
            period_mode=str(window.mode),
            period_start=start,
            period_end=end,
            period_label=window.label,
            period_detail=window.detail,
        )

        def attempt(name: str, action: Any) -> Any:
            """Run one query, logging and swallowing its failure."""
            try:
                return action()
            except Exception:  # noqa: BLE001
                LOGGER.debug("Dashboard query '%s' failed.", name, exc_info=True)
                return None

        # ------------------------------------------------------------------
        # Counted inside the period
        # ------------------------------------------------------------------
        snapshot.packets_in_period = attempt(
            "packets_in_period", lambda: self._traffic.packets_in_period(start, end)
        ) or 0
        snapshot.snort_alerts_in_period = attempt(
            "snort_alerts_in_period",
            lambda: self._alerts.count_alerts_in_period(start, end),
        ) or 0
        snapshot.anomalies_in_period = attempt(
            "anomalies_in_period",
            lambda: self._alerts.count_anomalies_in_period(start, end),
        ) or 0
        snapshot.findings_in_period = attempt(
            "findings_in_period",
            lambda: self._scans.count_findings_in_period(start, end),
        ) or 0
        snapshot.scans_in_period = attempt(
            "scans_in_period", lambda: self._scans.count_scans_in_period(start, end)
        ) or 0
        snapshot.hosts_seen_in_period = attempt(
            "hosts_seen_in_period",
            lambda: self._hosts.count_seen_in_period(start, end),
        ) or 0
        snapshot.hosts_discovered_in_period = attempt(
            "hosts_discovered",
            lambda: self._hosts.count_first_seen_in_period(start, end),
        ) or 0

        # Both sources, on the period's own bounds, so this agrees with the IDS
        # Alerts screen filtered to the same period rather than reporting
        # Snort's share of it. The headline total is the sum of these parts and
        # not a second query, which is what makes the tile and the donut
        # incapable of disagreeing.
        severity = attempt(
            "detections_by_severity",
            lambda: self._alerts.count_detections_by_severity(start, end),
        ) or {}
        snapshot.high_alerts = int(severity.get("HIGH", 0))
        snapshot.medium_alerts = int(severity.get("MEDIUM", 0))
        snapshot.low_alerts = int(severity.get("LOW", 0))
        snapshot.info_alerts = int(severity.get("INFO", 0))
        snapshot.severity_distribution = tuple(sorted(severity.items()))
        snapshot.detections_in_period = sum(int(v) for v in severity.values())

        snapshot.mean_detection_latency_seconds = attempt(
            "latency", lambda: self._alerts.mean_detection_latency(start, end)
        )

        # ------------------------------------------------------------------
        # Trends: the comparable preceding period, when one is stored
        # ------------------------------------------------------------------
        # Guarded like every other figure: a trend is the least important thing
        # on the page and must not be able to blank the rest of it.
        attempt("trends", lambda: self._add_trends(snapshot, window, attempt))

        # ------------------------------------------------------------------
        # Current state - no period bound, by design
        # ------------------------------------------------------------------
        snapshot.total_packets_stored = attempt(
            "total_packets", self._traffic.total_packets_observed
        ) or 0
        snapshot.last_packet_at = attempt("last_packet", self._traffic.last_packet_time)
        snapshot.observed_hosts = attempt("hosts_total", self._hosts.count_all) or 0
        snapshot.active_hosts = attempt(
            "hosts_active",
            lambda: self._hosts.count_active_since(
                utcnow() - timedelta(hours=ACTIVE_HOST_RECENCY_HOURS)
            ),
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
        snapshot.ids_alerts_total = attempt(
            "alerts_total", self._alerts.count_alerts
        ) or 0
        snapshot.last_alert_at = attempt("last_alert", self._alerts.last_alert_time)
        # The automated assessment picture, computed by the same function over
        # the same uncapped host query as the Vulnerability Assessment tiles,
        # inside the same scope - so the two screens cannot disagree.
        snapshot.assessment = attempt("assessment", self._assessment_summary)

        # ------------------------------------------------------------------
        # Series and lists
        # ------------------------------------------------------------------
        aggregates = attempt(
            "traffic_series", lambda: self._traffic.aggregates_between(start, end)
        ) or []
        snapshot.traffic_series = self._downsample_traffic(aggregates, chart_points)

        snapshot.alert_bucket_minutes = self._bucket_minutes(window)
        snapshot.alert_series = tuple(
            attempt(
                "alert_series",
                lambda: self._alerts.detections_per_interval(
                    start, end, minutes=snapshot.alert_bucket_minutes
                ),
            )
            or ()
        )
        protocols = attempt(
            "protocols", lambda: self._traffic.protocol_distribution(start, end)
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
        snapshot.recent_activity = tuple(
            attempt("recent_activity", lambda: self._audit.recent_activity(8)) or ()
        )
        # The threat timeline plots the alerts themselves - the security event
        # of record - rather than the correlated groups built from them.
        snapshot.threat_timeline = tuple(
            {
                "at": alert.effective_time,
                "severity": str(alert.severity),
                "label": alert.message or alert.signature_text,
            }
            for alert in attempt(
                "timeline",
                lambda: self._alerts.search_alerts(start=start, end=end, limit=30),
            ) or ()
        )
        return snapshot

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def set_scope_provider(self, provider: Any) -> None:
        """Attach the automatic assessment scope resolver.

        Set after construction because the assessment queue that owns the
        scope is built later in start-up.
        """
        self._scope_provider = provider

    def _assessment_summary(self) -> Any:
        """Assessment counts over every host, inside the current scope."""
        from aethra_sec.models.host import summarize_assessment

        provider = getattr(self, "_scope_provider", None)
        scope = provider() if provider is not None else None
        return summarize_assessment(self._hosts.assessment_summary_hosts(), scope)

    @staticmethod
    def _bucket_minutes(period: DashboardPeriod) -> int:
        """Chart bucket width that suits the span.

        A year bucketed into fifteen-minute slots is unreadable and expensive;
        a single day bucketed by the day is one bar. The width is chosen from
        the span, never from how much data happens to be in it.
        """
        span = period.duration_seconds
        if span is None or span > 180 * 86_400:
            return 1440 * 7
        if span > 40 * 86_400:
            return 1440
        if span > 3 * 86_400:
            return 180
        return 15

    def _add_trends(
        self, snapshot: DashboardSnapshot, period: DashboardPeriod, attempt: Any
    ) -> None:
        """Fill in the previous-period comparisons, where one is answerable.

        A trend arrow is only drawn when the database genuinely holds records
        covering the comparison span. With nothing stored that far back the
        fields stay ``None`` and the tile shows no arrow, rather than implying
        a 100% fall from a period that was never recorded (§1).
        """
        previous = period.previous()
        if previous is None or previous.start is None:
            return

        earliest_aggregate = attempt(
            "earliest_aggregate", self._traffic.earliest_aggregate_time
        )
        if earliest_aggregate is not None and earliest_aggregate <= previous.start:
            snapshot.packets_previous_period = attempt(
                "packets_previous",
                lambda: self._traffic.packets_in_period(previous.start, previous.end),
            )

        earliest_alert = attempt("earliest_alert", self._alerts.earliest_alert_time)
        if earliest_alert is not None and earliest_alert <= previous.start:
            snapshot.alerts_previous_period = attempt(
                "alerts_previous",
                lambda: sum(
                    int(v)
                    for v in (
                        self._alerts.count_detections_by_severity(
                            previous.start, previous.end
                        )
                        or {}
                    ).values()
                ),
            )

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
        self, session: Session, period: DashboardPeriod | None = None
    ) -> dict[str, Any]:
        """Network figures for the dashboard's top-talkers panel.

        Takes the same period as :meth:`snapshot`, so the panel describes the
        window the rest of the page is reporting on.

        This used to fetch top destinations, top ports and a second protocol
        distribution as well. The Dashboard displays none of them - the
        protocol donut is fed from the snapshot - and the top-ports query alone
        was measured at 18 seconds against 679k stored packets, because the
        optimiser prefers the ``dst_port`` index over the time range. Three
        queries whose results were discarded are not worth that on every load;
        they remain available, bounded, on :class:`TrafficRepository` for a
        caller that actually shows them.
        """
        self._access.require(session, Permission.DASHBOARD_VIEW)
        window = (period or DashboardPeriod.default()).refreshed()
        # The top-sources query groups every packet in the window by source, so
        # it is the most expensive query on the page (measured near 0.8s over
        # 100k+ rows even with its covering index). The panel changes slowly, so
        # the result is cached for a few seconds: repeated dashboard refreshes -
        # and the auto-refresh timer - serve the cache instead of re-running it,
        # which is what kept it from saturating the small connection pool.
        import time as _time

        # Keyed on the period *mode*, not its exact bounds: a rolling window's
        # end is "now" and drifts every call, so keying on the bounds never hit.
        # The TTL is what keeps it fresh; switching period changes the mode and
        # invalidates at once.
        key = str(window.mode)
        cached = self._overview_cache
        if cached is not None and cached[0] == key and (
            _time.monotonic() - cached[1]
        ) < self.OVERVIEW_TTL_SECONDS:
            return cached[2]
        try:
            overview = {
                "top_sources": self._traffic.top_sources(
                    window.start, 5, window.end
                ),
                "interfaces": self._traffic.distinct_interfaces(),
            }
        except Exception:  # noqa: BLE001
            LOGGER.debug("Network overview query failed.", exc_info=True)
            return {"top_sources": [], "interfaces": []}
        self._overview_cache = (key, _time.monotonic(), overview)
        return overview
