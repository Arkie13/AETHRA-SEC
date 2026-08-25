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

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Deque

from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import DetectionRuleDefinition, TrafficAnomaly
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


@dataclass
class DetectionThresholds:
    """Threshold values read from the settings service."""

    enabled: bool = True
    icmp_per_second: int = 50
    udp_per_second: int = 300
    syn_per_second: int = 100
    syn_unanswered_ratio: float = 0.8
    http_per_second: int = 80
    port_scan_ports: int = 20
    port_scan_window: int = 10
    host_sweep_hosts: int = 15
    host_sweep_window: int = 10
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
        if not self._should_fire(f"{RULE_ICMP_FLOOD}|{source}", timestamp, thresholds):
            return None
        return self._build(
            RULE_ICMP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.icmp_per_second),
            window=window,
            observation=(
                f"{source} sent {count} ICMP packet(s) in {window} second(s) "
                f"({rate:.1f} packets/second), which is at or above the "
                f"configured threshold of {thresholds.icmp_per_second} per second."
            ),
            evidence={
                "icmp_packets_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.icmp_per_second,
                "most_recent_destination": destination,
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
        if not self._should_fire(marker, timestamp, thresholds):
            return None
        return self._build(
            RULE_UDP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.udp_per_second),
            window=window,
            observation=(
                f"{source} sent {count} UDP packet(s) to "
                f"{destination}:{packet.dst_port} in {window} second(s) "
                f"({rate:.1f} packets/second), at or above the configured "
                f"threshold of {thresholds.udp_per_second} per second."
            ),
            evidence={
                "udp_packets_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.udp_per_second,
                "destination_port": packet.dst_port,
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
        if not self._should_fire(f"{RULE_SYN_FLOOD}|{source}", timestamp, thresholds):
            return None
        return self._build(
            RULE_SYN_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.syn_per_second),
            window=window,
            severity=Severity.HIGH,
            observation=(
                f"{source} sent {syn_count} TCP SYN packet(s) in {window} "
                f"second(s) ({rate:.1f}/second, threshold "
                f"{thresholds.syn_per_second}/second) while only {answered} "
                f"SYN/ACK reply packet(s) were observed - "
                f"{unanswered_ratio * 100:.0f}% of connection attempts were "
                "not seen to complete."
            ),
            evidence={
                "syn_packets_in_window": syn_count,
                "syn_ack_replies_observed": answered,
                "unanswered_ratio": round(unanswered_ratio, 3),
                "unanswered_ratio_threshold": thresholds.syn_unanswered_ratio,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.syn_per_second,
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
        """High rate of decoded HTTP traffic from one source."""
        window = thresholds.rate_window
        count = self._http[source].add(timestamp, window)
        rate = count / float(window)
        if rate < thresholds.http_per_second:
            return None
        if not self._should_fire(f"{RULE_HTTP_FLOOD}|{source}", timestamp, thresholds):
            return None
        return self._build(
            RULE_HTTP_FLOOD,
            packet,
            source=source,
            destination=destination,
            observed=rate,
            threshold=float(thresholds.http_per_second),
            window=window,
            observation=(
                f"{source} generated {count} decoded HTTP packet(s) in "
                f"{window} second(s) ({rate:.1f}/second), at or above the "
                f"configured threshold of {thresholds.http_per_second}/second."
            ),
            evidence={
                "http_packets_in_window": count,
                "window_seconds": window,
                "observed_rate_pps": round(rate, 2),
                "threshold_pps": thresholds.http_per_second,
                "destination": destination,
                "destination_port": packet.dst_port,
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

    def _check_host_sweep(
        self,
        packet: CapturedPacket,
        source: str,
        timestamp: float,
        thresholds: DetectionThresholds,
    ) -> TrafficAnomaly | None:
        """Many distinct destination hosts contacted in a short window."""
        window = thresholds.host_sweep_window
        destination = packet.dst_ip or packet.dst_mac
        tracker = self._sweep_hosts[source]
        distinct = tracker.add(timestamp, destination, window)
        if distinct < thresholds.host_sweep_hosts:
            return None
        if not self._should_fire(f"{RULE_HOST_SWEEP}|{source}", timestamp, thresholds):
            return None
        hosts = sorted(str(h) for h in tracker.distinct(timestamp, window))
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
                f"threshold of {thresholds.host_sweep_hosts} hosts."
            ),
            evidence={
                "distinct_hosts": distinct,
                "threshold_hosts": thresholds.host_sweep_hosts,
                "window_seconds": window,
                "hosts_sample": hosts[:40],
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _should_fire(
        self, marker: str, timestamp: float, thresholds: DetectionThresholds
    ) -> bool:
        """Suppression window: avoid re-raising the same finding constantly."""
        previous = self._last_fired.get(marker)
        if previous is not None and (timestamp - previous) < thresholds.suppression_window:
            return False
        self._last_fired[marker] = timestamp
        return True

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
            event_count=1,
            first_seen=packet.captured_at,
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
        icmp_per_second=as_int("detection.icmp_packets_per_second", 50),
        udp_per_second=as_int("detection.udp_packets_per_second", 300),
        syn_per_second=as_int("detection.tcp_syn_per_second", 100),
        syn_unanswered_ratio=as_float("detection.tcp_syn_unanswered_ratio", 0.8),
        http_per_second=as_int("detection.http_requests_per_second", 80),
        port_scan_ports=as_int("detection.port_scan_distinct_ports", 20),
        port_scan_window=as_int("detection.port_scan_window_seconds", 10),
        host_sweep_hosts=as_int("detection.host_sweep_distinct_hosts", 15),
        host_sweep_window=as_int("detection.host_sweep_window_seconds", 10),
        rate_window=as_int("detection.rate_window_seconds", 5),
        suppression_window=as_int("detection.suppression_window_seconds", 120),
    )
