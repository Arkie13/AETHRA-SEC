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
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Deque

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

#: The four flood rules whose severity comes from the measured packet rate.
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

#: Severity bands on the observed sustained rate:
#: Low below 500 pps, Medium 500-999 pps, High 1,000 pps and above.
#:
#: Both floors are INCLUSIVE and belong to the band above them: a measured
#: 500.0 pps is Medium and a measured 1,000.0 pps is High.
#:
#: These are the operative thresholds. They differ from the bands as written
#: in manuscript revision 9 §3.9.8 ("Low 100-500, Medium 501-1,000, High above
#: 1,000") at three points, each a deliberate decision recorded here:
#:
#:   * 500 pps is MEDIUM, not LOW. §3.9.8 put 500 at the top of the Low band.
#:   * 1,000 pps is HIGH, not MEDIUM. §3.9.8 put 1,000 at the top of the
#:     Medium band and started High above it.
#:   * Low has no lower floor. §3.9.8 started Low at 100 pps, which left a
#:     detected flood below 100 pps outside every band - reachable in normal
#:     operation, because the HTTP flood threshold is 10 requests per second.
#:     Anything under 500 pps is now simply Low.
#:
#: §3.9.8 needs updating to match, or the manuscript and the application will
#: disagree about a measured 500 pps and a measured 1,000 pps.
FLOOD_BAND_MEDIUM_FLOOR = 500.0
FLOOD_BAND_HIGH_FLOOR = 1000.0


@dataclass(frozen=True)
class FloodBand:
    """One severity band: its packet-rate range and what it is called.

    This is the single place the bands are written down. The classifier below
    and every screen that explains a severity read them from here, so a range
    shown to an operator cannot drift from the range actually applied.

    ``min_pps`` and ``max_pps`` are the integer bounds, for display. The
    classification itself compares the measured rate against the floors above,
    which is where a fractional rate such as 500.4 is decided.
    """

    severity: Severity
    label: str
    range_text: str
    description: str
    min_pps: int
    max_pps: int | None

    def summary(self) -> str:
        """One line, as an anomaly's evidence records it."""
        return f"{self.label.title()} ({self.range_text})"

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
        if self.min_pps == 0:
            # The lowest band is open at the bottom: any detected flood under
            # the Medium floor is Low. "0 to 499 pps" would read as though a
            # floor existed.
            return f"Below {self.max_pps + 1:,} pps"
        return f"{self.min_pps:,} to {self.max_pps:,} pps"


#: The severity bands, highest first.
FLOOD_BANDS: tuple[FloodBand, ...] = (
    FloodBand(
        severity=Severity.HIGH, label="HIGH", range_text="1,000 pps and above",
        description=(
            "High-volume flooding consistent with a denial-of-service "
            "condition."
        ),
        min_pps=1000, max_pps=None,
    ),
    FloodBand(
        severity=Severity.MEDIUM, label="MEDIUM", range_text="500-999 pps",
        description="Sustained abnormal traffic consistent with an active flood.",
        min_pps=500, max_pps=999,
    ),
    FloodBand(
        severity=Severity.LOW, label="LOW", range_text="< 500 pps",
        description="Traffic above the normal baseline but of limited volume.",
        min_pps=0, max_pps=499,
    ),
)


def flood_band(severity: Severity) -> FloodBand | None:
    """The band for a severity, or ``None`` where no band applies.

    Only these three severities are study-defined. Anything else - a review
    state, an application-scored severity - correctly gets ``None`` rather
    than a band invented to fill the space.
    """
    for band in FLOOD_BANDS:
        if band.severity is severity:
            return band
    return None


def flood_severity(rate_per_second: float) -> tuple[Severity, str]:
    """The severity band for a detected flood's sustained rate.

    The bands themselves are defined once, in :data:`FLOOD_BANDS`, and the
    floors they are compared against in the constants above. Both floors are
    INCLUSIVE: a rate landing exactly on one belongs to the band above it,
    not below. The numbers are deliberately not repeated here - a second copy
    in this docstring is how the stated bands and the applied ones drift
    apart, and a test checks this function's source for exactly that.

    Returns:
        ``(severity, band description)``. The description is taken from
        :data:`FLOOD_BANDS` so the range an operator reads and the comparison
        actually applied cannot drift apart.
    """
    if rate_per_second >= FLOOD_BAND_HIGH_FLOOR:
        return Severity.HIGH, FLOOD_BANDS[0].summary()
    if rate_per_second >= FLOOD_BAND_MEDIUM_FLOOR:
        return Severity.MEDIUM, FLOOD_BANDS[1].summary()
    return Severity.LOW, FLOOD_BANDS[2].summary()


#: A rate at or above this share of a threshold is worth saying out loud.
#: Below it the traffic is not close enough to be interesting and the log
#: would fill with ordinary background noise.
NEAR_MISS_FRACTION = 0.6

#: How often one source and rule may produce a near-miss line. A flood lasts
#: minutes and arrives as thousands of packets; this is per source per rule,
#: so a sustained one costs a line a minute rather than a line a packet.
NEAR_MISS_INTERVAL_SECONDS = 60.0

def _completes_handshake(packet: Any) -> bool:
    """True for a TCP segment with ACK set and neither SYN nor RST.

    That is the client's side of an established connection: the third packet
    of a completed handshake and everything it sends afterwards. A SYN flood
    sends none - its sender never completes a handshake, and when the target
    answers with SYN/ACK the sender's kernel replies RST, which is excluded.
    """
    flags = getattr(packet, "tcp_flags", None)
    return flags is not None and (flags & 0x16) == 0x10


#: How long a near miss stays on System Health after its traffic stops.
NEAR_MISS_LEDGER_SECONDS = 900.0

#: Most near misses kept at once. The ledger is keyed by source and rule, so
#: a spoofed flood could otherwise grow it without bound; past the cap the
#: oldest entry is dropped and the drop is counted.
NEAR_MISS_LEDGER_MAX = 200

#: How often, on the capture clock, idle per-key rule state is swept.
PRUNE_INTERVAL_SECONDS = 30.0

#: ICMP echo request and echo reply types, for IPv4 and IPv6.
ICMP_ECHO_REQUEST_TYPES: frozenset[int] = frozenset({8, 128})
ICMP_ECHO_REPLY_TYPES: frozenset[int] = frozenset({0, 129})


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
    #: Seconds without a qualifying observation after which an episode has
    #: ended and the next threshold crossing opens a new one. See
    #: evaluation/detection_major_revision/ATTACK_EPISODE_LIFECYCLE.md.
    episode_gap: int = 15
    #: Seconds between measurement updates for a flood already being
    #: reported. Suppression stops repeat ALERTS; this stops repeat WRITES.
    #: At one second an episode's rate is at most a second stale, while a
    #: 20,000 pps flood still produces one update a second rather than
    #: 20,000 database writes.
    measurement_interval: float = 1.0


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

    def count_recent(self, timestamp: float, window: float) -> int:
        """Count events inside the window WITHOUT trimming the history.

        :meth:`count` discards everything older than the window it is asked
        about. That is right for a counter only ever read at one window, and
        wrong for one shared by rules with different windows: asking a
        10-second counter for a 5-second count used to throw away the other
        five seconds, so the next 10-second reading came out low.
        """
        cutoff = timestamp - window
        total = 0
        for value in reversed(self.events):
            if value < cutoff:
                break
            if value <= timestamp:
                total += 1
        return total

    @property
    def newest(self) -> float | None:
        """Capture time of the most recent event, or ``None`` when empty."""
        return self.events[-1] if self.events else None


@dataclass
class _SlidingSet:
    """Distinct keys seen recently, trimmed to a window."""

    events: Deque[tuple[float, object]] = field(default_factory=deque)
    #: How many of ``events`` carry each key. Kept in step with ``events`` so
    #: the distinct count is ``len(counts)`` - O(1) per packet.
    #:
    #: ``add`` used to rebuild a set from every event in the window on every
    #: call. The host-sweep rule calls it for every packet sent to a real host,
    #: so during a 1,000 pps flood each packet paid for a 10,000-element set:
    #: profiled offline, this one line was 78% of rule-engine time and capped
    #: analysis at 847 packets/s against a 2,000 pps flood. The backlog that
    #: built up is what detections 2859/2860 recorded as a 27 s gap between a
    #: packet's capture time and its measurement, and the CPU it burned
    #: competed for the interpreter lock the Tk thread also needs (see
    #: evaluation/detection_major_revision/HIGH_SEVERITY_CRASH_ROOT_CAUSE.md).
    counts: dict[object, int] = field(default_factory=dict)

    def _expire(self, cutoff: float) -> None:
        events, counts = self.events, self.counts
        while events and events[0][0] < cutoff:
            _stamp, item = events.popleft()
            remaining = counts.get(item, 0) - 1
            if remaining > 0:
                counts[item] = remaining
            else:
                counts.pop(item, None)

    def add(self, timestamp: float, key: object, window: float) -> int:
        """Record a key and return the distinct count inside the window."""
        self.events.append((timestamp, key))
        self.counts[key] = self.counts.get(key, 0) + 1
        self._expire(timestamp - window)
        return len(self.counts)

    def distinct(self, timestamp: float, window: float) -> set[object]:
        """Distinct keys inside the window."""
        self._expire(timestamp - window)
        return set(self.counts)

    @property
    def newest(self) -> float | None:
        """Capture time of the most recent event, or ``None`` when empty."""
        return self.events[-1][0] if self.events else None


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
        #: ACKs a source sent with neither SYN nor RST set - the client's half
        #: of a completed handshake. See :meth:`_check_syn` for why this, and
        #: not the server's SYN/ACK, decides whether connections complete.
        self._syn_completed: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._http: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._scan_ports: dict[tuple[str, str], _SlidingSet] = defaultdict(_SlidingSet)
        self._sweep_hosts: dict[str, _SlidingSet] = defaultdict(_SlidingSet)
        #: Every packet a source sent, and every packet it sent to one target,
        #: so a port scan, a host sweep or a Snort alert can be graded on the
        #: same pps legend as a flood (§3.9.8) from a live, uncapped count.
        self._source_packets: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)
        self._pair_packets: dict[tuple[str, str], _SlidingCounter] = defaultdict(
            _SlidingCounter
        )
        #: Capture time of the newest packet seen, so a rate asked for from
        #: outside the capture thread is measured on the capture's own clock.
        self._latest_timestamp: float | None = None
        self._last_fired: dict[str, float] = {}
        #: Last measurement update per marker, for the cadence gate.
        self._last_measured: dict[str, float] = {}
        #: Largest distinct port/host count reported so far for a running port
        #: scan or host sweep, so growth can trigger a measurement update.
        #: Dropped when the episode ends (:meth:`_end_episode`).
        self._extent_reported: dict[str, int] = {}
        #: Last time a near miss was logged, per source and rule.
        self._near_miss: dict[str, float] = {}
        #: Recent traffic that approached a rule without raising a detection,
        #: per marker, with the PEAK rate it reached. Read by System Health so
        #: "no detections" can be told apart from "nothing came close".
        self._near_miss_ledger: dict[str, dict[str, Any]] = {}
        self._near_miss_evicted = 0
        #: Rate crossings a rule set aside because connections completed.
        self._syn_set_aside = 0
        #: Highest severity rank reported per marker inside its window.
        self._last_rank: dict[str, int] = {}
        #: Markers whose latest firing was a band escalation.
        self._escalated: set[str] = set()
        #: Capture time of the last ICMP echo REQUEST per (sender, target), so
        #: the target's echo REPLIES can be recognised as answers rather than
        #: counted as a flood of its own. See :meth:`_is_echo_answer`.
        self._icmp_last_request: dict[tuple[str, str], float] = {}
        self._icmp_answers_excluded = 0
        #: Capture time of the last QUALIFYING observation per marker - the
        #: episode clock. A gap longer than ``episode_gap`` ends the episode.
        self._last_qualified: dict[str, float] = {}
        #: Set by :meth:`_should_fire`, read once by :meth:`_build`.
        self._pending_start = False
        self._episodes_ended = 0
        #: Capture-clock time of the next sweep of idle per-key state.
        self._next_prune: float | None = None
        self._pruned_keys = 0
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
                "tracked_keys": self._tracked_keys(),
                "pruned_keys": self._pruned_keys,
                "icmp_echo_answers_excluded": self._icmp_answers_excluded,
                "episodes_ended": self._episodes_ended,
                "near_misses_tracked": len(self._near_miss_ledger),
                "near_misses_evicted": self._near_miss_evicted,
                "syn_crossings_set_aside": self._syn_set_aside,
            }

    def _tracked_keys(self) -> int:
        """Entries held across every per-key map - the engine's memory driver."""
        return (
            len(self._icmp) + len(self._udp) + len(self._syn) + len(self._syn_ack)
            + len(self._syn_completed) + len(self._http) + len(self._scan_ports) + len(self._sweep_hosts)
            + len(self._source_packets) + len(self._pair_packets)
            + len(self._last_fired) + len(self._last_measured)
            + len(self._extent_reported)
            + len(self._near_miss) + len(self._icmp_last_request)
            + len(self._last_qualified)
        )

    def _maybe_prune(self, timestamp: float, thresholds: DetectionThresholds) -> None:
        """Sweep idle per-key state once every ``PRUNE_INTERVAL_SECONDS``.

        Every map here is keyed by something the traffic chooses - a source, a
        source/target pair, a destination port - and a key was never removed
        once created. A counter is only trimmed when its own key sees another
        packet, so a DNS reply to a fresh ephemeral port left one entry behind
        for good: measured offline, 100,000 such packets left 60,000 keys and
        60 MB that were never released. Windows logged a RADAR_PRE_LEAK report
        for python.exe on 15 Oct 2026 during a long monitoring run.

        Only state that can no longer affect a decision is removed: a counter
        whose newest event is older than every window that reads it, and a
        suppression or cadence marker older than the interval it governs. A
        removed entry and an expired one produce identical decisions, which a
        regression test checks.
        """
        if self._next_prune is None:
            self._next_prune = timestamp + PRUNE_INTERVAL_SECONDS
            return
        if timestamp < self._next_prune:
            return
        self._next_prune = timestamp + PRUNE_INTERVAL_SECONDS
        self._prune(timestamp, thresholds)

    def _prune(self, now: float, thresholds: DetectionThresholds) -> int:
        """Remove idle state as of capture time ``now``. Returns entries removed."""
        horizon = now - (self._packet_window(thresholds) + 1.0)
        removed = 0
        for table in (
            self._icmp, self._udp, self._syn, self._syn_ack, self._syn_completed,
            self._http, self._scan_ports, self._sweep_hosts, self._source_packets,
            self._pair_packets,
        ):
            stale = [
                key for key, tracker in table.items()
                if tracker.newest is None or tracker.newest < horizon
            ]
            for key in stale:
                del table[key]
            removed += len(stale)

        suppression = now - max(1.0, float(thresholds.suppression_window))
        for marker in [m for m, t in self._last_fired.items() if t < suppression]:
            del self._last_fired[marker]
            self._last_rank.pop(marker, None)
            self._escalated.discard(marker)
            removed += 1
        cadence = now - max(1.0, float(thresholds.measurement_interval))
        for marker in [m for m, t in self._last_measured.items() if t < cadence]:
            del self._last_measured[marker]
            removed += 1
        quiet = now - NEAR_MISS_INTERVAL_SECONDS
        for marker in [m for m, t in self._near_miss.items() if t < quiet]:
            del self._near_miss[marker]
            removed += 1
        kept = now - NEAR_MISS_LEDGER_SECONDS
        for marker in [
            m for m, e in self._near_miss_ledger.items() if e["last_seen"] < kept
        ]:
            del self._near_miss_ledger[marker]
            removed += 1
        # An episode whose last qualifying observation is older than the gap
        # is over. Its suppression state goes with it - otherwise a marker kept
        # by the 120 s suppression would still block the next episode once its
        # episode clock had been swept.
        ended = now - float(thresholds.episode_gap)
        for marker in [m for m, t in self._last_qualified.items() if t < ended]:
            del self._last_qualified[marker]
            self._end_episode(marker)
            removed += 1
        answered = now - float(thresholds.rate_window)
        for pair in [p for p, t in self._icmp_last_request.items() if t < answered]:
            del self._icmp_last_request[pair]
            removed += 1
        self._pruned_keys += removed
        return removed

    def reset(self) -> None:
        """Clear all rule state (used when capture restarts)."""
        with self._lock:
            self._icmp.clear()
            self._udp.clear()
            self._syn.clear()
            self._syn_ack.clear()
            self._syn_completed.clear()
            self._http.clear()
            self._scan_ports.clear()
            self._sweep_hosts.clear()
            self._near_miss.clear()
            self._near_miss_ledger.clear()
            self._source_packets.clear()
            self._pair_packets.clear()
            self._icmp_last_request.clear()
            self._last_qualified.clear()
            self._pending_start = False
            self._next_prune = None
            self._latest_timestamp = None
            self._last_fired.clear()
            self._last_rank.clear()
            self._escalated.clear()
            self._last_measured.clear()
            self._extent_reported.clear()

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

            # Count every packet per source and per source->target pair before
            # any rule runs, so scans, sweeps and Snort alerts have a real pps
            # to be graded on. One direction only: the target's replies are
            # the target's packets, never counted as the source's.
            span = self._packet_window(thresholds)
            self._source_packets[source].add(timestamp, span)
            if destination:
                self._pair_packets[(source, destination)].add(timestamp, span)
            if self._latest_timestamp is None or timestamp > self._latest_timestamp:
                self._latest_timestamp = timestamp
            self._maybe_prune(timestamp, thresholds)

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
                elif _completes_handshake(packet):
                    self._syn_completed[source].add(
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

            # Only connection ATTEMPTS count towards a port scan. Counting
            # every packet of an established session is what made this rule
            # unusable in the inbound direction: a server answering 20 of this
            # host's own outbound connections lands on 20 distinct ephemeral
            # ports, which reads identically to one source touching 20 ports.
            #
            # Measured on this installation before the fix: of 173 inbound
            # "port scan" detections, 0 touched a single well-known service
            # port, every one hit only client-side ports, and the median share
            # of consecutive port numbers was 95% - the signature of reply
            # traffic, not of scanning. Outbound detections of real Nmap runs
            # were correct throughout (133 of 151 touched service ports), so
            # the rule's logic was sound and only its input was wrong.
            if destination and packet.dst_port is not None and self._initiates(
                packet, protocol
            ):
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

    def _note_near_miss(
        self,
        marker: str,
        rate: float,
        threshold: float,
        timestamp: float,
        unit: str = "packets/second",
        reason: str = "",
    ) -> None:
        """Record traffic that approached a rule without raising a detection.

        Answers the question a missing alert always raises - was the traffic
        too small, or did the rule set it aside? - with the numbers that
        settle it. Raises nothing.

        The ledger keeps the PEAK rate per source and rule. The log line is
        rate limited and is written when the rate first crosses
        ``NEAR_MISS_FRACTION`` of the threshold, so on its own it reports the
        ramp, not the traffic: every flood logged exactly 60% of its trigger
        on 16 Oct 2026, which read as capture loss and was not.

        ``reason`` is set when the rate DID cross the threshold and a second
        condition set the traffic aside; the near miss then says why.
        """
        if threshold <= 0 or rate < threshold * NEAR_MISS_FRACTION:
            return
        entry = self._near_miss_ledger.get(marker)
        if entry is None:
            if len(self._near_miss_ledger) >= NEAR_MISS_LEDGER_MAX:
                oldest = min(
                    self._near_miss_ledger,
                    key=lambda m: self._near_miss_ledger[m]["last_seen"],
                )
                del self._near_miss_ledger[oldest]
                self._near_miss_evicted += 1
            rule, _, source = marker.partition("|")
            entry = {
                "rule": rule, "source": source, "threshold": threshold,
                "unit": unit, "peak_rate": rate, "first_seen": timestamp,
                "last_seen": timestamp, "observations": 0, "reason": "",
            }
            self._near_miss_ledger[marker] = entry
        entry["observations"] += 1
        entry["last_seen"] = timestamp
        entry["threshold"] = threshold
        if rate > entry["peak_rate"]:
            entry["peak_rate"] = rate
        if reason:
            entry["reason"] = reason

        last = self._near_miss.get(marker)
        if last is not None and timestamp - last < NEAR_MISS_INTERVAL_SECONDS:
            return
        self._near_miss[marker] = timestamp
        if reason:
            LOGGER.info(
                "[NEAR-MISS] %s measured %.1f %s, at or above its threshold of "
                "%.1f, but no detection was raised: %s",
                marker, rate, unit, threshold, reason,
            )
            return
        LOGGER.info(
            "[NEAR-MISS] %s measured %.1f %s, below its configured threshold "
            "of %.1f - no detection raised. The rate logged here is the first "
            "crossing of %.0f%% of the threshold; the peak is tracked on "
            "System Health. Compare that peak with the rate actually sent "
            "before changing a threshold.",
            marker, rate, unit, threshold, NEAR_MISS_FRACTION * 100,
        )

    def near_misses(self) -> list[dict[str, Any]]:
        """Recent traffic that approached a rule and raised nothing, newest first.

        Each entry is what was measured: rule, source, peak rate, threshold,
        when it was first and last seen (capture clock, epoch seconds), how
        many evaluations it covered, and - when the rate crossed but the
        traffic was set aside - why. Nothing here is a detection.
        """
        with self._lock:
            entries = [dict(entry) for entry in self._near_miss_ledger.values()]
        entries.sort(key=lambda entry: entry["last_seen"], reverse=True)
        return entries

    def _is_echo_answer(
        self,
        packet: CapturedPacket,
        source: str,
        destination: str,
        timestamp: float,
        window: float,
    ) -> bool:
        """True when ``packet`` is an echo reply to a request the destination sent.

        Records echo requests as a side effect, so the reply that follows can
        be recognised. A packet whose ICMP type was not decoded is never
        treated as an answer: without the type there is no evidence it is one.
        """
        icmp_type = getattr(packet, "icmp_type", None)
        if icmp_type is None or not destination:
            return False
        if icmp_type in ICMP_ECHO_REQUEST_TYPES:
            self._icmp_last_request[(source, destination)] = timestamp
            return False
        if icmp_type in ICMP_ECHO_REPLY_TYPES:
            asked = self._icmp_last_request.get((destination, source))
            return asked is not None and 0 <= timestamp - asked <= window
        return False

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
        """Excessive ICMP rate from a single source.

        Echo replies that answer the destination's own echo requests are not
        counted. A ping flood made the TARGET look like a second attacker: on
        15 Oct 2026 the flood from 192.168.1.21 was recorded as detection 2859
        and, 0.09 ms later, the target's replies as detection 2860
        (192.168.1.26 -> .21), each with its own HIGH popup, siren and
        incident. The TCP rule already excludes SYN-ACKs for the same reason.
        An echo reply nobody asked for - a reply flood - is still counted.
        """
        window = thresholds.rate_window
        if self._is_echo_answer(packet, source, destination, timestamp, window):
            self._icmp_answers_excluded += 1
            return None
        count = self._icmp[source].add(timestamp, window)
        rate = count / float(window)
        if rate < thresholds.icmp_per_second:
            self._note_near_miss(
                f"{RULE_ICMP_FLOOD}|{source}", rate,
                float(thresholds.icmp_per_second), timestamp,
            )
            return None
        severity, band = flood_severity(rate)
        marker = f"{RULE_ICMP_FLOOD}|{source}"
        # Suppression governs ALERTS, not measurement. A flood already being
        # reported still has its rate, count and last-seen time updated, so
        # the episode reflects what the traffic is doing now rather than what
        # it was doing when its band was entered.
        measurement_only = not self._should_fire(
            marker, timestamp, thresholds, severity
        )
        if measurement_only and not self._should_measure(
            marker, timestamp, thresholds.measurement_interval
        ):
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
            measurement_only=measurement_only,
            evidence={
                "icmp_packets_in_window": count,
                "rate_scope": (
                    "ICMP packets sent BY this source, over the stated window, "
                    "excluding echo replies that answer the destination's own "
                    "echo requests. Not the interface total: the Traffic Rate "
                    "graph sums every packet in both directions, requests and "
                    "replies alike, so during a ping flood it reads about twice "
                    "this value."
                ),
                "measurement_scope": "per-source, one direction",
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
            self._note_near_miss(
                f"{RULE_UDP_FLOOD}|{source}", rate,
                float(thresholds.udp_per_second), timestamp,
            )
            return None
        marker = f"{RULE_UDP_FLOOD}|{source}|{destination}|{packet.dst_port}"
        severity, band = flood_severity(rate)
        # Suppression governs ALERTS, not measurement. A flood already being
        # reported still has its rate, count and last-seen time updated, so
        # the episode reflects what the traffic is doing now rather than what
        # it was doing when its band was entered.
        measurement_only = not self._should_fire(
            marker, timestamp, thresholds, severity
        )
        if measurement_only and not self._should_measure(
            marker, timestamp, thresholds.measurement_interval
        ):
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
            measurement_only=measurement_only,
            evidence={
                "udp_packets_in_window": count,
                "rate_scope": (
                    "UDP packets sent BY this source to this destination and port, "
                    "over the stated window. Not the interface total shown on the "
                    "Traffic Rate graph, which sums every protocol in both "
                    "directions."
                ),
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
        """High SYN rate from one source whose connections do not complete.

        "Complete" is decided by the SOURCE's own ACKs (no SYN, no RST), not
        by the target's SYN/ACK replies. A SYN/ACK is the server accepting an
        attempt; it says nothing about the client finishing it. Counting it
        as completion meant a SYN flood aimed at a LISTENING port - one the
        server answers - was set aside as "connections completing" while not
        one handshake finished. On 16 Oct 2026 that left one TCP-SYN
        detection against 142 ICMP and 125 UDP for the same test runs, every
        SYN burst aimed at XAMPP's Apache on port 80. The earlier detections
        that did fire were the ones fast enough to overflow the backlog, so
        the replies stopped.

        The threshold and ratio are unchanged; only what counts as a
        completed connection is corrected. The SYN/ACK count stays in the
        evidence. Trade-off, stated: a source flooding SYNs while it also
        carries a busy established connection has those ACKs counted as
        completions, which can only hide that flood, never invent one.
        """
        window = thresholds.rate_window
        syn_count = self._syn[source].add(timestamp, window)
        rate = syn_count / float(window)
        marker = f"{RULE_SYN_FLOOD}|{source}"
        if rate < thresholds.syn_per_second:
            self._note_near_miss(
                marker, rate, float(thresholds.syn_per_second), timestamp,
            )
            return None

        answered = self._syn_ack[source].count(timestamp, window)
        completed = self._syn_completed[source].count(timestamp, window)
        unanswered_ratio = (
            1.0 - min(1.0, completed / float(syn_count)) if syn_count else 0.0
        )
        if unanswered_ratio < thresholds.syn_unanswered_ratio:
            # The source is completing its connections, so this is a high
            # connection rate rather than a flood. Recorded, not dropped
            # silently: an operator missing an alert can see the reason.
            self._syn_set_aside += 1
            self._note_near_miss(
                marker, rate, float(thresholds.syn_per_second), timestamp,
                reason=(
                    f"the source completed handshakes for "
                    f"{(1.0 - unanswered_ratio) * 100:.0f}% of its {syn_count} "
                    f"SYNs ({completed} ACK(s) in {window} s), below the "
                    f"{thresholds.syn_unanswered_ratio * 100:.0f}% unanswered "
                    "share a flood requires"
                ),
            )
            return None
        severity, band = flood_severity(rate)
        # Suppression governs ALERTS, not measurement. A flood already being
        # reported still has its rate, count and last-seen time updated, so
        # the episode reflects what the traffic is doing now rather than what
        # it was doing when its band was entered.
        measurement_only = not self._should_fire(
            marker, timestamp, thresholds, severity
        )
        if measurement_only and not self._should_measure(
            marker, timestamp, thresholds.measurement_interval
        ):
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
                f"{thresholds.syn_per_second}/second) and completed only "
                f"{completed} handshake ACK(s) in that window "
                f"({answered} SYN/ACK repl(ies) from the target were seen) - "
                f"{unanswered_ratio * 100:.0f}% of connection attempts were "
                f"not seen to complete. Severity band: {band}."
            ),
            measurement_only=measurement_only,
            evidence={
                "syn_packets_in_window": syn_count,
                "rate_scope": (
                    "TCP SYN packets sent BY this source, over the stated window. "
                    "Not the interface total shown on the Traffic Rate graph, which "
                    "sums every protocol in both directions."
                ),
                "syn_ack_replies_observed": answered,
                "handshake_acks_from_source": completed,
                "completion_basis": (
                    "A connection counts as completed only when the source "
                    "sends its own ACK (no SYN, no RST). The target's SYN/ACK "
                    "replies are listed for reference and do not count."
                ),
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
            self._note_near_miss(
                f"{RULE_HTTP_FLOOD}|{source}", rate,
                float(thresholds.http_per_second), timestamp,
                unit="requests/second",
            )
            return None
        severity, band = flood_severity(rate)
        marker = f"{RULE_HTTP_FLOOD}|{source}"
        # Suppression governs ALERTS, not measurement. A flood already being
        # reported still has its rate, count and last-seen time updated, so
        # the episode reflects what the traffic is doing now rather than what
        # it was doing when its band was entered.
        measurement_only = not self._should_fire(
            marker, timestamp, thresholds, severity
        )
        if measurement_only and not self._should_measure(
            marker, timestamp, thresholds.measurement_interval
        ):
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
            measurement_only=measurement_only,
            evidence={
                "http_requests_in_window": count,
                "rate_scope": (
                    "HTTP requests sent BY this source, over the stated window. "
                    "Responses are not requests and are not counted. Not the "
                    "interface total shown on the Traffic Rate graph."
                ),
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

    #: Destination ports at or above this are client-side by convention
    #: (IANA dynamic/private range), so a UDP packet arriving at one is a
    #: reply to something this host sent, not a probe of a service.
    EPHEMERAL_PORT_FLOOR = 49152

    @staticmethod
    def _initiates(packet: Any, protocol: str) -> bool:
        """Whether this packet is an attempt to open a conversation.

        TCP is exact: a SYN with no ACK is a connection attempt and nothing
        else. UDP has no handshake, so the honest approximation is the
        destination port - a probe targets a service port, a reply arrives at
        the ephemeral port the client chose.

        The trade-off, stated rather than hidden: a UDP scan that targets only
        ports above 49152 is not counted. That is accepted deliberately, the
        same way the UDP flood rule accepts missing a flood spoofed from port
        443 - a rule that fires on ordinary browsing teaches an operator to
        ignore the alert screen, which costs more detection than the gap does.
        """
        if protocol == "TCP":
            return bool(getattr(packet, "is_syn_only", False))
        if protocol == "UDP":
            port = getattr(packet, "dst_port", None)
            try:
                return int(port) < AnomalyRuleEngine.EPHEMERAL_PORT_FLOOR
            except (TypeError, ValueError):
                return False
        return False

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
        # Suppression governs ALERTS, not measurement - the same split the
        # flood rules use. The packet that first reaches the threshold is
        # necessarily AT it (20 ports, 20 probes in the window, ~2 pps), so a
        # scan recorded only at that instant read "20 ports, 2.4 pps" whether
        # it went on to probe 20 ports or 1,200. A running scan now sends
        # rate-limited measurement updates so its record reaches the real
        # extent and rate.
        measurement_only = not self._should_fire(marker, timestamp, thresholds)
        if not self._extent_due(
            marker, distinct, timestamp, thresholds, opening=not measurement_only
        ):
            return None
        ports = sorted(int(p) for p in tracker.distinct(timestamp, window))
        # Detection is by distinct ports; the SEVERITY is graded on the same
        # pps legend as a flood, from the packets this source sent this target.
        pps = round(self._pps(source, destination, timestamp, window), 1)
        severity, band_summary = flood_severity(pps)
        return self._build(
            RULE_PORT_SCAN,
            packet,
            source=source,
            destination=destination,
            observed=float(distinct),
            threshold=float(thresholds.port_scan_ports),
            window=window,
            severity=severity,
            observation=(
                f"{source} contacted {distinct} distinct destination port(s) "
                f"on {destination} within {window} second(s), at or above the "
                f"configured threshold of {thresholds.port_scan_ports} ports. "
                f"It sent {pps:g} pps to that host: {band_summary}."
            ),
            measurement_only=measurement_only,
            evidence={
                "distinct_ports": distinct,
                "threshold_ports": thresholds.port_scan_ports,
                "window_seconds": window,
                "ports_sample": ports[:40],
                "protocol": packet.protocol,
                "packets_per_second": pps,
                "packets_in_window": self._window_packets(
                    source, destination, timestamp, window
                ),
                "rate_scope": (
                    "Packets this source sent this destination over the stated "
                    "window, divided by the window. Not the interface total."
                ),
                "severity_basis": "pps legend (§3.9.8)",
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
        marker = f"{RULE_HOST_SWEEP}|{source}"
        # Suppression governs ALERTS, not measurement (see _check_port_scan).
        # On 19 Oct 2026 192.168.1.222 ARP-swept 192.168.1.0/24 once a minute,
        # ~190-240 addresses over ~7.6 s. Each burst was recorded at the 15th
        # host - "15 hosts, 1.5 pps" - and the rest were seen and discarded,
        # so a subnet sweep at ~23 pps read as an alert at 1.5 pps.
        measurement_only = not self._should_fire(marker, timestamp, thresholds)
        if not self._extent_due(
            marker, distinct, timestamp, thresholds, opening=not measurement_only
        ):
            return None
        # Detection is by distinct hosts; the SEVERITY is graded on the same
        # pps legend as a flood, from every packet this source sent.
        pps = round(self._pps(source, None, timestamp, window), 1)
        severity, band_summary = flood_severity(pps)
        return self._build(
            RULE_HOST_SWEEP,
            packet,
            source=source,
            destination="",
            observed=float(distinct),
            threshold=float(thresholds.host_sweep_hosts),
            window=window,
            severity=severity,
            observation=(
                f"{source} contacted {distinct} distinct destination host(s) "
                f"within {window} second(s), at or above the configured "
                f"threshold of {thresholds.host_sweep_hosts} hosts, with "
                f"{concentration:.0%} of them inside {subnet} - a range being "
                "walked rather than scattered outbound traffic. "
                f"It sent {pps:g} pps: {band_summary}."
            ),
            measurement_only=measurement_only,
            evidence={
                "distinct_hosts": distinct,
                "threshold_hosts": thresholds.host_sweep_hosts,
                "window_seconds": window,
                "hosts_sample": hosts[:40],
                "target_range": subnet,
                "range_concentration": round(concentration, 3),
                "threshold_concentration": thresholds.host_sweep_concentration,
                "packets_per_second": pps,
                "packets_in_window": self._window_packets(
                    source, None, timestamp, window
                ),
                "rate_scope": (
                    "Every packet this source sent over the stated window, "
                    "divided by the window. Not the interface total."
                ),
                "severity_basis": "pps legend (§3.9.8)",
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _packet_window(thresholds: DetectionThresholds) -> float:
        """How long the per-source packet counters keep their history.

        Long enough for every window that grades on them: the flood rate
        window, the port-scan window and the host-sweep window.
        """
        return float(max(
            thresholds.rate_window,
            thresholds.port_scan_window,
            thresholds.host_sweep_window,
            1,
        ))

    def _pps(
        self, source: str, destination: str | None, timestamp: float, window: float
    ) -> float:
        """Packets per second ``source`` sent (to ``destination`` if given).

        Counted over the ``window`` seconds up to ``timestamp`` on the capture
        clock. One-directional.
        """
        if window <= 0:
            return 0.0
        if destination:
            counter = self._pair_packets.get((source, destination))
        else:
            counter = self._source_packets.get(source)
        if counter is None:
            return 0.0
        return counter.count_recent(timestamp, window) / float(window)

    def _window_packets(
        self, source: str, destination: str | None, timestamp: float, window: float
    ) -> int:
        """The packet count N behind :meth:`_pps`, so pps = N / window is auditable."""
        if window <= 0:
            return 0
        if destination:
            counter = self._pair_packets.get((source, destination))
        else:
            counter = self._source_packets.get(source)
        if counter is None:
            return 0
        return counter.count_recent(timestamp, window)

    def source_rate(
        self, src_ip: str, dst_ip: str | None = None, window: float | None = None
    ) -> float | None:
        """Live pps a source is sending, for grading a detection made elsewhere.

        Used to grade a Snort alert on the same §3.9.8 pps legend as the
        flood rules. Measured on the capture's own clock, over the rate window
        unless one is given. ``None`` when capture has seen no packet at all,
        so the caller can tell "no rate available" from "rate is zero".
        """
        if not src_ip:
            return None
        with self._lock:
            if self._latest_timestamp is None:
                return None
            span = window or float(self._thresholds.rate_window or 5)
            # A capture that has gone quiet - stopped, or never delivering -
            # would otherwise answer with the rate of traffic from minutes or
            # hours ago. That is not this alert's traffic, so it is no answer.
            if time.time() - self._latest_timestamp > max(10.0, 2 * span):
                return None
            return round(
                self._pps(src_ip, dst_ip or None, self._latest_timestamp, span), 1
            )

    def _end_episode(self, marker: str) -> None:
        """Forget one marker's alert state because its episode has ended.

        Only that marker: another source, target or rule keeps its own state.
        Rate counters are untouched - they hold real packet history and trim
        themselves to their window.
        """
        self._last_fired.pop(marker, None)
        self._last_rank.pop(marker, None)
        self._escalated.discard(marker)
        self._last_measured.pop(marker, None)
        self._extent_reported.pop(marker, None)
        self._episodes_ended += 1

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
        # Episode boundary. This is only ever called once the rule's own
        # detection condition holds, so ``timestamp`` is a qualifying
        # observation. If the previous qualifying observation for this marker
        # is older than the episode gap, that episode has ENDED and this one
        # starts a new episode - whatever the suppression window says.
        #
        # Before this, the 120 s suppression window was the only boundary, and
        # the store folded on the same 120 s measured from the episode's LAST
        # observation. A test run that began less than two minutes after the
        # previous one ended was folded into it, and each fold moved the end
        # forward: detection 2825 (15 Oct 2026) is one record covering six
        # separate ICMP bursts with gaps of 5, 47, 12, 88 and 64 s.
        last_qualified = self._last_qualified.get(marker)
        new_episode = (
            last_qualified is None
            or timestamp - last_qualified > thresholds.episode_gap
        )
        if new_episode and last_qualified is not None:
            self._end_episode(marker)
            LOGGER.info(
                "[EPISODE] %s: no qualifying observation for %.1f s (gap %d s) - "
                "the previous episode ended; this crossing opens a new one.",
                marker, timestamp - last_qualified, thresholds.episode_gap,
            )
        self._last_qualified[marker] = timestamp
        self._pending_start = new_episode
        # The rule qualified, so whatever this source did on the way up was a
        # ramp, not a miss.
        self._near_miss_ledger.pop(marker, None)

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

    def _should_measure(self, marker: str, timestamp: float,
                        interval: float) -> bool:
        """Whether this episode is due another measurement update.

        Separate from :meth:`_should_fire`, which governs alerts. A flood
        under way needs its rate kept current, but not once per packet: at
        high rates that would be a database write per packet, which is how a
        detection pipeline stalls the interface it is meant to inform.
        """
        if interval <= 0:
            return True
        previous = self._last_measured.get(marker)
        if previous is not None and (timestamp - previous) < interval:
            return False
        self._last_measured[marker] = timestamp
        return True

    def _extent_due(
        self,
        marker: str,
        distinct: int,
        timestamp: float,
        thresholds: DetectionThresholds,
        *,
        opening: bool,
    ) -> bool:
        """Whether a port scan or host sweep should report its extent now.

        The packet that opens the episode always reports. After that, a
        running scan reports once per measurement interval, like a flood, and
        also as soon as its distinct count has doubled since it last reported:
        a sweep can cover a whole /24 inside one interval and stop before the
        next, which left its record at whatever the first update saw. Doubling
        keeps the extra writes logarithmic - 15, 30, 60, 120, 240 hosts.
        """
        reported = self._extent_reported.get(marker, 0)
        if opening:
            due = True
            self._last_measured[marker] = timestamp
        elif reported and distinct >= 2 * reported:
            due = True
            self._last_measured[marker] = timestamp
        else:
            due = self._should_measure(
                marker, timestamp, thresholds.measurement_interval
            )
        if due:
            self._extent_reported[marker] = max(reported, distinct)
        return due

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
        measurement_only: bool = False,
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

        # Read once: the flag belongs to the _should_fire call that preceded
        # this build. A measurement-only update never starts an episode.
        starts_episode = self._pending_start and not measurement_only
        self._pending_start = False
        return TrafficAnomaly(
            measurement_only=measurement_only,
            starts_episode=starts_episode,
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
            # One record is one observation. This was max(1, int(observed)) -
            # the measured RATE (or port / host count) - so a new ICMP
            # detection started at "120 events" and every later measurement
            # added one: detection 2860's "Events: 158" was 120 + 38.
            event_count=1,
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
        episode_gap=as_int("detection.episode_gap_seconds", 15),
    )
