"""Deterministic traffic-analysis detection rules (§24, §91).

Six rules, all threshold-based, all fed exclusively by packets PyShark actually
delivered. Each rule states what it measured, against which threshold, over
which window - so a detection can be audited rather than trusted.

Deliberate wording (§24): these rules describe *behaviour*, not proven attacks.
Titles read "Port scanning behaviour detected", "Potential TCP SYN flood",
"Traffic anomaly" - never "attack confirmed".

There is no machine learning here and none is wanted (§87).
"""

from __future__ import annotations

import ipaddress

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Deque

from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import DetectionRuleDefinition, TrafficAnomaly
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("analytics.anomaly_rules")

RULE_ICMP_FLOOD = "RULE-ICMP-RATE"
RULE_UDP_FLOOD = "RULE-UDP-RATE"
RULE_SYN_FLOOD = "RULE-TCP-SYN-RATE"
RULE_HTTP_FLOOD = "RULE-HTTP-RATE"
RULE_PORT_SCAN = "RULE-PORT-SCAN"
RULE_HOST_SWEEP = "RULE-HOST-SWEEP"


RULE_DEFINITIONS: tuple[DetectionRuleDefinition, ...] = (
    DetectionRuleDefinition(
        rule_id=RULE_ICMP_FLOOD,
        title="Excessive ICMP traffic",
        category=ThreatCategory.ICMP_FLOOD,
        description=(
            "Counts ICMP packets sent by each source address inside a sliding "
            "window and reports sources exceeding the configured rate."
        ),
        threshold_setting="detection.icmp_packets_per_second",
        window_setting="detection.rate_window_seconds",
        base_severity=Severity.MEDIUM,
        why_it_matters=(
            "ICMP is normally low-volume control traffic. A sustained high "
            "rate is used for ping floods and for mapping which hosts are "
            "alive, though monitoring systems can produce the same pattern."
        ),
        what_to_check=(
            "Identify the source host and whether it is a monitoring system. "
            "Confirm the destination is still responsive."
        ),
    ),
    DetectionRuleDefinition(
        rule_id=RULE_UDP_FLOOD,
        title="UDP flood indicator",
        category=ThreatCategory.UDP_FLOOD,
        description=(
            "Counts UDP packets per source toward a single destination port "
            "inside a sliding window."
        ),
        threshold_setting="detection.udp_packets_per_second",
        window_setting="detection.rate_window_seconds",
        base_severity=Severity.MEDIUM,
        why_it_matters=(
            "UDP is connectionless, so a high rate can saturate a link or "
            "overwhelm a service with no handshake required."
        ),
        what_to_check=(
            "Identify the destination service, confirm it should be exposed, "
            "and check the destination host's resource usage."
        ),
    ),
    DetectionRuleDefinition(
        rule_id=RULE_SYN_FLOOD,
        title="Potential TCP SYN flood",
        category=ThreatCategory.TCP_SYN_FLOOD,
        description=(
            "Counts TCP SYN packets per source and compares them with the "
            "SYN/ACK replies observed for the same source, reporting a high "
            "rate of connection attempts that are not being completed."
        ),
        threshold_setting="detection.tcp_syn_per_second",
        window_setting="detection.rate_window_seconds",
        base_severity=Severity.HIGH,
        why_it_matters=(
            "Half-open connections consume a server's connection table. A "
            "sustained flood can make a service unavailable to legitimate "
            "users."
        ),
        what_to_check=(
            "Confirm the destination service still answers legitimate "
            "clients, and review rate limiting in front of it."
        ),
    ),
    DetectionRuleDefinition(
        rule_id=RULE_HTTP_FLOOD,
        title="Abnormal HTTP request volume",
        category=ThreatCategory.HTTP_FLOOD,
        description=(
            "Counts decoded HTTP packets per source inside a sliding window. "
            "Only fires where HTTP is actually visible and decodable."
        ),
        threshold_setting="detection.http_requests_per_second",
        window_setting="detection.rate_window_seconds",
        base_severity=Severity.MEDIUM,
        why_it_matters=(
            "High request volume can exhaust application resources even when "
            "network bandwidth is fine, because each request may cost database "
            "queries or rendering work."
        ),
        what_to_check=(
            "Review the web service's own access logs for the same window and "
            "confirm the service is still responding."
        ),
    ),
    DetectionRuleDefinition(
        rule_id=RULE_PORT_SCAN,
        title="Port scanning behaviour detected",
        category=ThreatCategory.PORT_SCAN,
        description=(
            "Counts distinct destination ports contacted by one source on one "
            "destination host inside a sliding window."
        ),
        threshold_setting="detection.port_scan_distinct_ports",
        window_setting="detection.port_scan_window_seconds",
        base_severity=Severity.MEDIUM,
        why_it_matters=(
            "Contacting many ports in a short interval is how an attacker "
            "enumerates the services a host exposes before choosing a target. "
            "Authorised vulnerability scanners produce the same pattern."
        ),
        what_to_check=(
            "Determine whether the source was authorised to scan, and review "
            "which of the contacted ports are actually open."
        ),
    ),
    DetectionRuleDefinition(
        rule_id=RULE_HOST_SWEEP,
        title="Network sweep behaviour detected",
        category=ThreatCategory.HOST_SWEEP,
        description=(
            "Counts distinct destination hosts contacted by one source inside "
            "a sliding window."
        ),
        threshold_setting="detection.host_sweep_distinct_hosts",
        window_setting="detection.host_sweep_window_seconds",
        base_severity=Severity.MEDIUM,
        why_it_matters=(
            "A sweep identifies which addresses are live, narrowing the target "
            "list before more focused probing."
        ),
        what_to_check=(
            "Identify the source and whether a discovery or monitoring tool "
            "runs from that address on this schedule."
        ),
    ),
)

RULE_BY_ID: dict[str, DetectionRuleDefinition] = {r.rule_id: r for r in RULE_DEFINITIONS}

#: The four flood rules whose severity the manuscript defines (§3.9.8).
FLOOD_RULES: frozenset[str] = frozenset(
    {RULE_ICMP_FLOOD, RULE_UDP_FLOOD, RULE_SYN_FLOOD, RULE_HTTP_FLOOD}
)

#: Manuscript §3.9.8 detection thresholds: 200 pps TCP SYN, 300 pps UDP,
#: 120 pps ICMP and 600 HTTP requests per minute (10 per second).
MANUSCRIPT_THRESHOLDS: dict[str, int] = {
    "detection.tcp_syn_per_second": 200,
    "detection.udp_packets_per_second": 300,
    "detection.icmp_packets_per_second": 120,
    "detection.http_requests_per_second": 10,
}

#: Manuscript §3.9.8 severity bands on the observed sustained rate:
#: Low 100-500 pps, Medium 501-1,000 pps, High above 1,000 pps.
FLOOD_BAND_LOW_FLOOR = 100.0
FLOOD_BAND_MEDIUM_FLOOR = 500.0
FLOOD_BAND_HIGH_FLOOR = 1000.0


@dataclass(frozen=True)
class FloodBand:
    """One §3.9.8 severity band: its range, and what the manuscript calls it.

    This is the single place the bands are written down. The classifier below
    and every screen that explains a severity read them from here, so a range
    shown to an operator cannot drift from the range actually applied.

    ``min_pps`` and ``max_pps`` are the manuscript's integer bounds, for
    display. The classification itself compares the measured rate against the
    floors above, which is where a fractional rate such as 500.4 is decided.
    """

    severity: Severity
    label: str
    range_text: str
    description: str
    min_pps: int
    max_pps: int | None

    def summary(self) -> str:
        """One line, as an anomaly's evidence records it."""
        return f"{self.label.title()} ({self.range_text}, manuscript §3.9.8)"

    def explain(self) -> str:
        """The tooltip text: what the band is, and what it means."""
        return (
            f"{self.label} SEVERITY\n\n"
            f"Threshold:\n{self.threshold_text}\n\n"
            f"Criteria:\n{self.description}"
        )

    @property
    def threshold_text(self) -> str:
        """The range as prose, e.g. "Greater than 1,000 pps"."""
        if self.max_pps is None:
            return f"Greater than {self.min_pps - 1:,} pps"
        return f"{self.min_pps:,} to {self.max_pps:,} pps"


#: The §3.9.8 bands, highest first. Wording is the manuscript's.
FLOOD_BANDS: tuple[FloodBand, ...] = (
    FloodBand(
        severity=Severity.HIGH, label="HIGH", range_text="> 1,000 pps",
        description=(
            "High-volume flooding consistent with a denial-of-service "
            "condition."
        ),
        min_pps=1001, max_pps=None,
    ),
    FloodBand(
        severity=Severity.MEDIUM, label="MEDIUM", range_text="501-1,000 pps",
        description="Sustained abnormal traffic consistent with an active flood.",
        min_pps=501, max_pps=1000,
    ),
    FloodBand(
        severity=Severity.LOW, label="LOW", range_text="100-500 pps",
        description="Traffic above the normal baseline but of limited volume.",
        min_pps=100, max_pps=500,
    ),
)


def flood_band(severity: Severity) -> FloodBand | None:
    """The §3.9.8 band for a severity, or ``None`` where the study defines none.

    Only these three severities are study-defined. Anything else - a review
    state, an application-scored severity - correctly gets ``None`` rather
    than a band invented to fill the space.
    """
    for band in FLOOD_BANDS:
        if band.severity is severity:
            return band
    return None


def flood_severity(rate_per_second: float) -> tuple[Severity, str]:
    """The §3.9.8 severity band for a detected flood's sustained rate.

    Returns:
        ``(severity, band description)``. A detection below the manuscript's
        Low floor (possible only when an administrator lowers a threshold
        beneath 100 pps) is still reported LOW - the lowest band - and the
        description says it fell below the band rather than pretending it
        was inside it.
    """
    # The band descriptions come from FLOOD_BANDS so that the text an operator
    # reads and the comparison actually applied cannot drift apart.
    if rate_per_second > FLOOD_BAND_HIGH_FLOOR:
        return Severity.HIGH, FLOOD_BANDS[0].summary()
    if rate_per_second > FLOOD_BAND_MEDIUM_FLOOR:
        return Severity.MEDIUM, FLOOD_BANDS[1].summary()
    if rate_per_second >= FLOOD_BAND_LOW_FLOOR:
        return Severity.LOW, FLOOD_BANDS[2].summary()
    return Severity.LOW, (
        f"Low - {rate_per_second:.1f} pps is below the manuscript's 100 pps "
        "Low floor (§3.9.8); reported at the lowest band"
    )


@dataclass
class DetectionThresholds:
    """Threshold values read from the settings service.

    The flood defaults are the manuscript's §3.9.8 thresholds.
    """

    enabled: bool = True
    icmp_per_second: int = 120
    udp_per_second: int = 300
    syn_per_second: int = 200
    syn_unanswered_ratio: float = 0.8
    #: 10 requests per second is the manuscript's 600 requests per minute.
    http_per_second: int = 10
    port_scan_ports: int = 20
    port_scan_window: int = 10
    host_sweep_hosts: int = 15
    host_sweep_window: int = 10
    #: Share of the contacted addresses that must fall inside one /24 before
    #: the pattern counts as a sweep. A sweep walks a range; a browser reaches
    #: scattered public addresses. Configurable so a site whose traffic looks
    #: different can tune it rather than live with the wrong answer.
    host_sweep_concentration: float = 0.75
    rate_window: int = 5
    suppression_window: int = 120


@dataclass
class _SlidingCounter:
    """Timestamps of recent events, trimmed to a window."""

    events: Deque[float] = field(default_factory=deque)

    def add(self, timestamp: float, window: float) -> int:
        """Record an event and return the count inside the window."""
        self.events.append(timestamp)
        cutoff = timestamp - window
        while self.events and self.events[0] < cutoff:
            self.events.popleft()
        return len(self.events)

    def count(self, timestamp: float, window: float) -> int:
        """Count events inside the window without recording a new one."""
        cutoff = timestamp - window
        while self.events and self.events[0] < cutoff:
            self.events.popleft()
        return len(self.events)


@dataclass
class _SlidingSet:
    """Distinct keys seen recently, trimmed to a window."""

    events: Deque[tuple[float, object]] = field(default_factory=deque)

    def add(self, timestamp: float, key: object, window: float) -> int:
        """Record a key and return the distinct count inside the window."""
        self.events.append((timestamp, key))
        cutoff = timestamp - window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        return len({item for _, item in self.events})

    def distinct(self, timestamp: float, window: float) -> set[object]:
        """Distinct keys inside the window."""
        cutoff = timestamp - window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        return {item for _, item in self.events}


class AnomalyRuleEngine:
    """Applies the deterministic detection rules to observed packets."""

    def __init__(
        self,
        thresholds: DetectionThresholds | None = None,
        *,
        trusted_addresses: set[str] | None = None,
    ) -> None:
        """Create the engine.

        Args:
            thresholds: configured thresholds; defaults are used when omitted.
            trusted_addresses: registered assets. Trust does not suppress a
                detection - it is recorded as evidence so the analyst can weigh
                it (§93).
        """
        self._thresholds = thresholds or DetectionThresholds()
        self._trusted = trusted_addresses or set()
        self._lock = threading.RLock()

        self._icmp: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._udp: dict[tuple[str, str, int], _SlidingCounter] = defaultdict(_SlidingCounter)
        self._syn: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._syn_ack: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._http: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._scan_ports: dict[tuple[str, str], _SlidingSet] = defaultdict(_SlidingSet)
        self._sweep_hosts: dict[str, _SlidingSet] = defaultdict(_SlidingSet)
        self._last_fired: dict[str, float] = {}
        #: Highest severity rank reported per marker inside its window.
        self._last_rank: dict[str, int] = {}
        #: Markers whose latest firing was a band escalation.
        self._escalated: set[str] = set()
        self._evaluations = 0
        self._fired = 0

    def update_thresholds(self, thresholds: DetectionThresholds) -> None:
        """Apply new thresholds without restarting capture."""
        with self._lock:
            self._thresholds = thresholds

    def update_trusted(self, addresses: set[str]) -> None:
        """Refresh the registered-asset list."""
        with self._lock:
            self._trusted = set(addresses)

    @property
    def statistics(self) -> dict[str, int]:
        """Real counters for the System Health screen."""
        with self._lock:
            return {
                "packets_evaluated": self._evaluations,
                "anomalies_raised": self._fired,
                "tracked_sources": len(self._icmp) + len(self._syn) + len(self._http),
            }

    def reset(self) -> None:
        """Clear all rule state (used when capture restarts)."""
        with self._lock:
            self._icmp.clear()
            self._udp.clear()
            self._syn.clear()
            self._syn_ack.clear()
            self._http.clear()
            self._scan_ports.clear()
            self._sweep_hosts.clear()
            self._last_fired.clear()
            self._last_rank.clear()
            self._escalated.clear()

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate(self, packet: CapturedPacket) -> list[TrafficAnomaly]:
        """Apply every rule to one packet.

        Returns:
            Anomalies that fired for this packet - usually empty. Each carries
            the measured value, the threshold and the window, so the operator
            can audit the judgement.
        """
        with self._lock:
            thresholds = self._thresholds
            if not thresholds.enabled:
                return []
            self._evaluations += 1

            source = packet.src_ip or packet.src_mac
            if not source:
                return []
            destination = packet.dst_ip or packet.dst_mac
            timestamp = packet.captured_at.timestamp()
            protocol = (packet.protocol or "").upper()
            results: list[TrafficAnomaly] = []

            if protocol.startswith("ICMP"):
                found = self._check_icmp(packet, source, destination, timestamp, thresholds)
                if found:
                    results.append(found)

            if protocol == "UDP" and packet.dst_port is not None and destination:
                found = self._check_udp(packet, source, destination, timestamp, thresholds)
                if found:
                    results.append(found)

            if protocol == "TCP":
                if packet.is_syn_ack:
                    self._syn_ack[destination or source].add(
                        timestamp, thresholds.rate_window
                    )
                elif packet.is_syn_only:
                    found = self._check_syn(
                        packet, source, destination, timestamp, thresholds
                    )
                    if found:
                        results.append(found)

            if (packet.app_protocol or "").upper() in ("HTTP", "HTTP2"):
                found = self._check_http(packet, source, destination, timestamp, thresholds)
                if found:
                    results.append(found)

            if destination and packet.dst_port is not None and protocol in ("TCP", "UDP"):
                found = self._check_port_scan(
                    packet, source, destination, timestamp, thresholds
                )
                if found:
                    results.append(found)

            if destination:
                found = self._check_host_sweep(packet, source, timestamp, thresholds)
                if found:
                    results.append(found)

            self._fired += len(results)
            return results

    # ------------------------------------------------------------------
    # Individual rules
    # ------------------------------------------------------------------
    def _check_icmp(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """Excessive ICMP rate from a single source."""
        window = thresholds.rate_window
        count = self._icmp[source].add(timestamp, window)
        rate = count / float(window)
        if rate < thresholds.icmp_per_second:
            return None
        severity, band = flood_severity(rate)
        marker = f"{RULE_ICMP_FLOOD}|{source}"
        if not self._should_fire(marker, timestamp, thresholds, severity):
            return None
        band += self._escalation_note(marker)
        return self._build(
            RULE_ICMP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.icmp_per_second),
            window=window,
            severity=severity,
            observation=(
                f"{source} sent {count} ICMP packet(s) in {window} second(s) "
                f"({rate:.1f} packets/second), which is at or above the "
                f"configured threshold of {thresholds.icmp_per_second} per second. "
                f"Severity band: {band}."
            ),
            evidence={
                "icmp_packets_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.icmp_per_second,
                "most_recent_destination": destination,
                "severity_band": band,
            },
        )

    def _check_udp(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """High UDP rate toward one destination port."""
        window = thresholds.rate_window
        key = (source, destination, int(packet.dst_port or 0))
        count = self._udp[key].add(timestamp, window)
        rate = count / float(window)
        if rate < thresholds.udp_per_second:
            return None
        marker = f"{RULE_UDP_FLOOD}|{source}|{destination}|{packet.dst_port}"
        severity, band = flood_severity(rate)
        if not self._should_fire(marker, timestamp, thresholds, severity):
            return None
        band += self._escalation_note(marker)
        return self._build(
            RULE_UDP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.udp_per_second),
            window=window,
            severity=severity,
            observation=(
                f"{source} sent {count} UDP packet(s) to "
                f"{destination}:{packet.dst_port} in {window} second(s) "
                f"({rate:.1f} packets/second), at or above the configured "
                f"threshold of {thresholds.udp_per_second} per second. "
                f"Severity band: {band}."
            ),
            evidence={
                "udp_packets_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.udp_per_second,
                "destination_port": packet.dst_port,
                "severity_band": band,
            },
        )

    def _check_syn(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """High SYN rate with few observed SYN/ACK replies."""
        window = thresholds.rate_window
        syn_count = self._syn[source].add(timestamp, window)
        rate = syn_count / float(window)
        if rate < thresholds.syn_per_second:
            return None

        answered = self._syn_ack[source].count(timestamp, window)
        unanswered_ratio = 1.0 - min(1.0, answered / float(syn_count)) if syn_count else 0.0
        if unanswered_ratio < thresholds.syn_unanswered_ratio:
            # Connections are completing, so this is high traffic rather than a
            # flood indicator. Saying so is the honest outcome.
            return None
        severity, band = flood_severity(rate)
        marker = f"{RULE_SYN_FLOOD}|{source}"
        if not self._should_fire(marker, timestamp, thresholds, severity):
            return None
        band += self._escalation_note(marker)
        return self._build(
            RULE_SYN_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.syn_per_second),
            window=window,
            severity=severity,
            observation=(
                f"{source} sent {syn_count} TCP SYN packet(s) in {window} "
                f"second(s) ({rate:.1f}/second, threshold "
                f"{thresholds.syn_per_second}/second) while only {answered} "
                f"SYN/ACK reply packet(s) were observed - "
                f"{unanswered_ratio * 100:.0f}% of connection attempts were "
                f"not seen to complete. Severity band: {band}."
            ),
            evidence={
                "syn_packets_in_window": syn_count,
                "syn_ack_replies_observed": answered,
                "unanswered_ratio": round(unanswered_ratio, 3),
                "unanswered_ratio_threshold": thresholds.syn_unanswered_ratio,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.syn_per_second,
                "severity_band": band,
            },
        )

    def _check_http(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """High rate of HTTP requests from one source.

        The manuscript's threshold is in requests (§3.9.8: 600 per minute), so
        a decoded HTTP *response* - one carrying a status code and no method -
        is not counted. Where the decoder supplied neither field the packet
        cannot be told apart and is counted, which can only make the rule more
        sensitive, never hide a flood.
        """
        if packet.http_status is not None and not packet.http_method:
            return None
        window = thresholds.rate_window
        count = self._http[source].add(timestamp, window)
        rate = count / float(window)
        if rate < thresholds.http_per_second:
            return None
        severity, band = flood_severity(rate)
        marker = f"{RULE_HTTP_FLOOD}|{source}"
        if not self._should_fire(marker, timestamp, thresholds, severity):
            return None
        band += self._escalation_note(marker)
        return self._build(
            RULE_HTTP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.http_per_second),
            window=window,
            severity=severity,
            observation=(
                f"{source} sent {count} HTTP request(s) in {window} second(s) "
                f"({rate:.1f}/second, {rate * 60:.0f}/minute), at or above the "
                f"configured threshold of {thresholds.http_per_second}/second "
                f"({thresholds.http_per_second * 60}/minute). "
                f"Severity band: {band}."
            ),
            evidence={
                "http_requests_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "observed_requests_per_minute": round(rate * 60, 1),
                "threshold_pps": thresholds.http_per_second,
                "threshold_requests_per_minute": thresholds.http_per_second * 60,
                "destination": destination,
                "destination_port": packet.dst_port,
                "severity_band": band,
            },
        )

    def _check_port_scan(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """Many distinct destination ports contacted in a short window."""
        window = thresholds.port_scan_window
        tracker = self._scan_ports[(source, destination)]
        distinct = tracker.add(timestamp, int(packet.dst_port or 0), window)
        if distinct < thresholds.port_scan_ports:
            return None
        marker = f"{RULE_PORT_SCAN}|{source}|{destination}"
        if not self._should_fire(marker, timestamp, thresholds):
            return None
        ports = sorted(int(p) for p in tracker.distinct(timestamp, window))
        return self._build(
            RULE_PORT_SCAN,
            packet,
            source=source,
            destination=destination,
            observed=float(distinct),
            threshold=float(thresholds.port_scan_ports),
            window=window,
            observation=(
                f"{source} contacted {distinct} distinct destination port(s) "
                f"on {destination} within {window} second(s), at or above the "
                f"configured threshold of {thresholds.port_scan_ports} ports."
            ),
            evidence={
                "distinct_ports": distinct,
                "threshold_ports": thresholds.port_scan_ports,
                "window_seconds": window,
                "ports_sample": ports[:40],
                "protocol": packet.protocol,
            },
        )

    @staticmethod
    def _is_probeable_host(destination: str) -> bool:
        """True when ``destination`` is an address a host could actually hold.

        Broadcast, multicast and unspecified addresses are not hosts that were
        contacted, and ARP and discovery protocols name them constantly, so
        counting them turned routine chatter into a sweep.
        """
        value = (destination or "").strip().lower()
        if not value:
            return False
        if value in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "255.255.255.255"}:
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            # A MAC that is not the broadcast address still names one device.
            return True
        return not (
            address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or address.is_loopback
        )

    @staticmethod
    def _range_concentration(hosts: list[str]) -> tuple[float, str]:
        """How tightly the contacted addresses cluster in one /24.

        A sweep walks a range, so most of its destinations share a prefix.
        Ordinary outbound traffic reaches scattered addresses that do not.

        Returns:
            The largest share falling in a single /24, and that range's name.
            Non-IP destinations (ARP by MAC) are treated as one range, because
            they are by definition confined to the local segment.
        """
        if not hosts:
            return 0.0, "-"
        counts: dict[str, int] = {}
        for host in hosts:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                counts["local segment"] = counts.get("local segment", 0) + 1
                continue
            if address.version != 4:
                counts["ipv6"] = counts.get("ipv6", 0) + 1
                continue
            prefix = str(ipaddress.ip_network(f"{host}/24", strict=False))
            counts[prefix] = counts.get(prefix, 0) + 1
        subnet, top = max(counts.items(), key=lambda item: item[1])
        return top / len(hosts), subnet

    def _check_host_sweep(
        self,
        packet: CapturedPacket,
        source: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """One source probing many addresses across a local range.

        Counting distinct destinations alone is not evidence of a sweep. A
        browser opening one page contacts well over the threshold of distinct
        addresses in a few seconds, which is why this machine was repeatedly
        reported as sweeping its own network. Two further conditions separate
        discovery from ordinary use, and both are recorded as evidence:

        * The destination must be a real host. Broadcast, multicast and
          unspecified addresses are not hosts contacted, and ARP asks about
          them constantly.
        * The addresses must sit in one local range. A sweep walks a subnet;
          a browser reaches scattered public addresses that share no prefix.

        Both are configurable, and an incident is not raised when the evidence
        does not meet them.
        """
        window = thresholds.host_sweep_window
        destination = packet.dst_ip or packet.dst_mac
        if not self._is_probeable_host(destination):
            return None
        tracker = self._sweep_hosts[source]
        distinct = tracker.add(timestamp, destination, window)
        if distinct < thresholds.host_sweep_hosts:
            return None

        hosts = sorted(str(h) for h in tracker.distinct(timestamp, window))
        concentration, subnet = self._range_concentration(hosts)
        if concentration < thresholds.host_sweep_concentration:
            # Many destinations, but scattered - ordinary outbound traffic.
            return None
        if not self._should_fire(f"{RULE_HOST_SWEEP}|{source}", timestamp, thresholds):
            return None
        return self._build(
            RULE_HOST_SWEEP,
            packet,
            source=source,
            destination="",
            observed=float(distinct),
            threshold=float(thresholds.host_sweep_hosts),
            window=window,
            observation=(
                f"{source} contacted {distinct} distinct destination host(s) "
                f"within {window} second(s), at or above the configured "
                f"threshold of {thresholds.host_sweep_hosts} hosts, with "
                f"{concentration:.0%} of them inside {subnet} - a range being "
                "walked rather than scattered outbound traffic."
            ),
            evidence={
                "distinct_hosts": distinct,
                "threshold_hosts": thresholds.host_sweep_hosts,
                "window_seconds": window,
                "hosts_sample": hosts[:40],
                "target_range": subnet,
                "range_concentration": round(concentration, 3),
                "threshold_concentration": thresholds.host_sweep_concentration,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _should_fire(
        self,
        marker: str,
        timestamp: float,
        thresholds: DetectionThresholds,
        severity: Severity | None = None,
    ) -> bool:
        """Suppression window: avoid re-raising the same finding constantly.

        With a ``severity``, a flood already reported inside the window is
        reported again when - and only when - its measured rate has entered a
        higher §3.9.8 band. Detection fires the moment the sliding rate first
        crosses the threshold, which is necessarily near the threshold; without
        this, a flood that went on to 1,400 pps stayed recorded at the band of
        its first second.
        """
        previous = self._last_fired.get(marker)
        rank = severity.rank if severity is not None else -1
        if previous is not None and (timestamp - previous) < thresholds.suppression_window:
            if severity is None or rank <= self._last_rank.get(marker, -1):
                return False
            self._escalated.add(marker)
        else:
            self._escalated.discard(marker)
        self._last_fired[marker] = timestamp
        if severity is not None:
            self._last_rank[marker] = rank
        return True

    def _escalation_note(self, marker: str) -> str:
        """Observation suffix for a band escalation, else empty."""
        if marker in self._escalated:
            return (
                " Reported again because the sustained rate entered a higher "
                "severity band than when this flood was first detected."
            )
        return ""

    def _build(
        self,
        rule_id: str,
        packet: CapturedPacket,
        *,
        source: str,
        destination: str,
        observed: float,
        threshold: float,
        window: int,
        observation: str,
        evidence: dict[str, object],
        severity: Severity | None = None,
    ) -> TrafficAnomaly:
        """Assemble an anomaly record with full, auditable evidence."""
        definition = RULE_BY_ID[rule_id]
        source_trusted = source in self._trusted
        destination_trusted = bool(destination) and destination in self._trusted
        if source_trusted:
            evidence = dict(evidence)
            evidence["source_is_registered_trusted_asset"] = True
        if destination_trusted:
            evidence = dict(evidence)
            evidence["destination_is_registered_trusted_asset"] = True

        confidence = 60
        if source_trusted:
            confidence -= 15
        if observed >= threshold * 2:
            confidence += 15

        return TrafficAnomaly(
            rule_id=rule_id,
            category=definition.category,
            title=definition.title,
            observation=observation,
            why_it_matters=definition.why_it_matters,
            what_to_check=definition.what_to_check,
            severity=severity or definition.base_severity,
            confidence=max(5, min(95, confidence)),
            src_ip=source,
            dst_ip=destination,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            interface=packet.interface,
            observed_value=observed,
            threshold_value=threshold,
            window_seconds=window,
            # The window the rule actually counted over, not a single instant.
            # Both bounds used to be the triggering packet's timestamp, which
            # made the stored window a point: an analyst could read that 300
            # packets had been counted but could not select those packets,
            # because the two fields that should delimit them were equal. It
            # also produced anomalies whose creation time preceded their own
            # first_seen, since the packet clock and the system clock are not
            # the same clock and the gap between them was all there was.
            event_count=max(1, int(observed)),
            # T2: taken here, where the threshold is actually crossed, and
            # never derived from when the row is written.
            detected_at=utcnow(),
            first_seen=packet.captured_at - timedelta(seconds=window),
            last_seen=packet.captured_at,
            evidence=evidence,
            source=EvidenceSource.PYSHARK,
        )


def thresholds_from_settings(get: Callable[[str, object], object]) -> DetectionThresholds:
    """Build :class:`DetectionThresholds` from the settings service.

    Args:
        get: a ``settings.get(key, default)`` callable.
    """

    def as_int(key: str, default: int) -> int:
        try:
            return int(str(get(key, default)))
        except (TypeError, ValueError):
            return default

    def as_float(key: str, default: float) -> float:
        try:
            return float(str(get(key, default)))
        except (TypeError, ValueError):
            return default

    def as_bool(key: str, default: bool) -> bool:
        value = get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    return DetectionThresholds(
        enabled=as_bool("detection.enabled", True),
        icmp_per_second=as_int("detection.icmp_packets_per_second", 120),
        udp_per_second=as_int("detection.udp_packets_per_second", 300),
        syn_per_second=as_int("detection.tcp_syn_per_second", 200),
        syn_unanswered_ratio=as_float("detection.tcp_syn_unanswered_ratio", 0.8),
        http_per_second=as_int("detection.http_requests_per_second", 10),
        port_scan_ports=as_int("detection.port_scan_distinct_ports", 20),
        port_scan_window=as_int("detection.port_scan_window_seconds", 10),
        host_sweep_hosts=as_int("detection.host_sweep_distinct_hosts", 15),
        host_sweep_concentration=as_float(
            "detection.host_sweep_range_concentration", 0.75
        ),
        host_sweep_window=as_int("detection.host_sweep_window_seconds", 10),
        rate_window=as_int("detection.rate_window_seconds", 5),
        suppression_window=as_int("detection.suppression_window_seconds", 120),
    )
