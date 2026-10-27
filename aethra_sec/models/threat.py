"""Traffic-analysis anomaly models (§24).

These records describe *observations*, not confirmed attacks. The wording used
throughout ("Potential ...", "... behaviour detected", "Traffic anomaly") is
deliberate: a deterministic threshold rule provides evidence, not proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    Severity,
    ThreatCategory,
)


@dataclass
class TrafficAnomaly:
    """A deterministic traffic rule that fired on real observations.

    Attributes:
        rule_id: stable identifier of the rule that fired.
        observation: exactly what was measured, in plain language.
        why_it_matters: educational explanation (§53).
        what_to_check: the analyst's next step.
        evidence: measured values (counts, rates, window length, thresholds).
        observed_value / threshold_value: the numbers behind the decision, so
            the operator can audit the judgement instead of trusting it.
    """

    id: int | None = None
    rule_id: str = ""
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    title: str = ""
    observation: str = ""
    why_it_matters: str = ""
    what_to_check: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    interface: str = ""
    #: The PEAK measurement across the episode, kept with GREATEST on every
    #: fold. Not the latest one - see ``latest_value``.
    observed_value: float = 0.0
    #: The most recent measurement, which is what CURRENT severity is
    #: classified from. ``None`` where no repeat has been folded in yet, or on
    #: rows written before the column existed.
    latest_value: float | None = None
    #: When ``latest_value`` was measured.
    latest_measured_at: datetime | None = None
    #: True when this observation is an update to a flood already being
    #: reported, rather than a new finding. It folds into the running episode
    #: and never creates a row or an alert of its own. Transient: it describes
    #: this observation, not the stored record, and is never persisted.
    measurement_only: bool = False
    #: True when this observation OPENS a new episode: the rule's previous
    #: qualifying observation was longer ago than ``detection.episode_gap_
    #: seconds``. The store then records a new detection instead of folding
    #: it into an earlier one. Transient, like ``measurement_only``.
    starts_episode: bool = False
    #: The highest severity the episode reached. Never falls, so an attack
    #: that touched HIGH is still reported as having done so after the rate
    #: drops back. ``None`` where it was never derived.
    peak_severity: Severity | None = None
    threshold_value: float = 0.0
    window_seconds: int = 0
    event_count: int = 1
    #: T2 - the instant the rule crossed its threshold, taken from the
    #: clock at that moment. Distinct from ``created_at``, which is when
    #: the row reached the database: without both, a slow detection and a
    #: slow write are indistinguishable.
    detected_at: datetime | None = None
    #: When an analyst marked this reviewed. A read receipt, deliberately
    #: separate from ``evaluation``: being looked at is not a verdict, and
    #: the evaluation labels feed the detection-accuracy statistics.
    reviewed_at: datetime | None = None
    reviewed_by: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    host_id: int | None = None
    incident_id: int | None = None
    evaluation: EvaluationLabel = EvaluationLabel.UNCLASSIFIED
    source: EvidenceSource = EvidenceSource.PYSHARK
    created_at: datetime | None = None

    # ------------------------------------------------------------------
    # Observed episode
    # ------------------------------------------------------------------
    @property
    def episode_severity(self) -> Severity:
        """The worst severity this episode has validly reached.

        This is what ``severity`` holds. It is raised by a higher measurement
        and never lowered (``AlertRepository.update_anomaly_occurrence``), so
        the badge, counters, filters and notifications describe what the
        attack reached rather than what it happens to be doing at the moment.
        """
        return self.severity

    @property
    def current_severity(self) -> Severity:
        """The band of the most recent measurement.

        Not ``severity``. This property used to return it, under a docstring
        saying it was "updated in place" - true once, but ``severity`` was
        later made raise-only, so "current severity" in the detail view was
        the episode's worst, and a flood that had fallen to 299 pps could be
        labelled HIGH beside a latest rate of 299.

        For the four flood rules the severity IS the measured rate's band, so
        the latest measurement decides it. With no repeat measurement folded
        in yet the trigger measurement is the latest one, and ``severity`` was
        classified from it. Every other rule grades on something other than
        the latest packet rate, and keeps ``severity``.
        """
        from aethra_sec.analytics.anomaly_rules import FLOOD_RULES, flood_severity

        if self.rule_id not in FLOOD_RULES or self.latest_value is None:
            return self.severity
        try:
            rate = float(self.latest_value)
        except (TypeError, ValueError):
            return self.severity
        if rate <= 0:
            return self.severity
        band, _summary = flood_severity(rate)
        return band

    @property
    def highest_severity(self) -> Severity:
        """The peak, falling back to the current value when none was derived.

        A record whose peak was never recorded has, as far as anything can be
        shown, reached at least its current severity. That is a floor taken
        from the row itself, not a guess about an unobserved escalation.
        """
        if self.peak_severity is None:
            return self.severity
        return (
            self.peak_severity
            if self.peak_severity.rank >= self.severity.rank
            else self.severity
        )

    @property
    def latest_rate(self) -> float | None:
        """The most recent measurement, or ``None`` when none was recorded.

        Never falls back to ``observed_value``: that is the peak, and
        presenting a peak as the current rate would overstate what is
        happening now.
        """
        return self.latest_value

    @property
    def escalated(self) -> bool:
        """True when the episode once stood higher than it does now."""
        return self.highest_severity.rank > self.severity.rank

    @property
    def first_observed(self) -> datetime | None:
        """When matching activity was first seen."""
        return self.first_seen or self.detected_at

    @property
    def last_observed(self) -> datetime | None:
        """When matching activity was last seen.

        ``None`` means it was never recorded, not that it never happened.
        """
        return self.last_seen

    def observation_count(self) -> tuple[int | None, str]:
        """Observations in this record, and how the number is known.

        Records from the 15 Oct 2026 revision start at 1 and add one per
        measurement (evidence ``measurement_clock: packet``) - "counted".
        Older records started ``event_count`` at the rule's measured value
        (the trigger rate for a flood) and added one per measurement. For an
        older flood record the trigger rate is stored, so the count is
        recovered exactly - "derived". For an older scan or sweep it is not,
        and ``None`` is returned - "unrecoverable" - rather than a guess.
        """
        from aethra_sec.analytics.anomaly_rules import FLOOD_RULES

        stored = int(self.event_count or 0)
        evidence = self.evidence or {}
        if evidence.get("measurement_clock") == "packet":
            return max(1, stored), "counted"
        trigger = evidence.get("observed_rate_pps")
        if self.rule_id in FLOOD_RULES and trigger is not None:
            try:
                derived = stored - int(float(trigger)) + 1
            except (TypeError, ValueError):
                derived = 0
            if derived >= 1:
                return derived, "derived"
        return None, "unrecoverable"

    @property
    def occurrences(self) -> int:
        """How many matching events this record stands for."""
        return max(1, int(self.event_count or 1))

    def episode(self, *, inactivity_seconds: int | None = None,
                now: datetime | None = None):
        """Summarise the observed episode.

        Computed on read from the stored timestamps, never stored, so a
        record that survives a restart is re-judged against the clock rather
        than keeping a stale verdict.
        """
        from aethra_sec.analytics.episodes import (
            DEFAULT_INACTIVITY_SECONDS, describe,
        )

        return describe(
            self.first_observed, self.last_observed, self.occurrences,
            inactivity_seconds=(
                DEFAULT_INACTIVITY_SECONDS if inactivity_seconds is None
                else inactivity_seconds
            ),
            now=now,
        )

    @property
    def dedup_key(self) -> str:
        """Key used to suppress repeat records inside the suppression window."""
        return f"{self.rule_id}|{self.src_ip}|{self.dst_ip}|{self.dst_port or ''}"

    @property
    def summary(self) -> str:
        """One-line description for tables and the threat timeline."""
        if self.src_ip and self.dst_ip:
            return f"{self.title}: {self.src_ip} -> {self.dst_ip}"
        if self.src_ip:
            return f"{self.title}: {self.src_ip}"
        return self.title

    def evidence_lines(self) -> tuple[str, ...]:
        """Evidence rendered as readable ``key: value`` lines."""
        return tuple(f"{key}: {value}" for key, value in sorted(self.evidence.items()))


@dataclass
class DetectionRuleDefinition:
    """Static description of a deterministic detection rule.

    Used by the Help screen and by reports to explain *how* a detection was
    made, which is a stated requirement of the educational design (§53, §86).
    """

    rule_id: str
    title: str
    category: ThreatCategory
    description: str
    threshold_setting: str
    window_setting: str
    base_severity: Severity
    why_it_matters: str
    what_to_check: str
    source: EvidenceSource = EvidenceSource.PYSHARK


@dataclass
class ThreatSummary:
    """Counts used by the dashboard security overview, all query-derived."""

    active_incidents: int = 0
    #: No ``critical_alerts``: CRITICAL is outside the detection severity
    #: model, so a field for it could only ever hold zero.
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    info_alerts: int = 0
    open_findings: int = 0
    anomalies_today: int = 0
    unresolved_incidents: int = 0

    @property
    def total_alerts(self) -> int:
        """Total alerts across all severities in the queried window."""
        return (
            self.high_alerts
            + self.medium_alerts
            + self.low_alerts
            + self.info_alerts
        )

    @property
    def has_data(self) -> bool:
        """False when nothing has been recorded yet."""
        return bool(
            self.total_alerts
            or self.active_incidents
            or self.open_findings
            or self.anomalies_today
        )
