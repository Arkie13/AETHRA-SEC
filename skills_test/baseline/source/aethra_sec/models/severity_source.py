"""Where a severity value came from, and what it is therefore worth.

The manuscript defines severity for exactly one kind of event. Revision 9
(§3.9.8, "Flood Traffic Severity Classification") classifies a detected flood
by its sustained packet rate - Low 100-500 pps, Medium 501-1,000 pps, High
above 1,000 pps - following NIST SP 800-94's threshold-based volumetric
approach. It defines no severity for port scans, host sweeps or Snort
signatures, and no CRITICAL band for detections.

That leaves the application showing severities from four sources that are not
equivalent, and this module records which is which.

:attr:`SeveritySource.MANUSCRIPT_FLOOD_BAND`
    The §3.9.8 rate band, applied to ICMP, UDP, TCP SYN and HTTP flood
    detections from the measured rate recorded in the detection's evidence.
    The only severity the study defines.

:attr:`SeveritySource.SNORT_PRIORITY`
    Derived from the priority a real Snort sensor put in the alert it sent.
    This is Snort's own prioritisation, mapped one-to-one and not reweighted,
    so it stays traceable to the sensor's rule set. Where a sensor sends no
    priority the alert is recorded MEDIUM and the absence is shown, rather
    than being guessed.

:attr:`SeveritySource.APPLICATION_SCORE`
    Computed by AETHRA-SEC's own risk engine from a numeric score. **This is an
    application field, not a manuscript-defined research measure.**

:attr:`SeveritySource.RULE_BASELINE`
    The baseline severity a non-flood detection rule carries (port scan, host
    sweep), again an application choice.

Why stored records are not re-banded
------------------------------------
Detections raised before the §3.9.8 bands were adopted keep the severity they
were raised with; each one's evidence records the rule, rate and threshold it
was judged by. Rewriting them would change historical records by arithmetic.
"""

from __future__ import annotations

from aethra_sec.models.enums import EvidenceSource, Severity, StrEnum


class SeveritySource(StrEnum):
    """What produced a severity value."""

    #: The manuscript's §3.9.8 flood rate band.
    MANUSCRIPT_FLOOD_BAND = "MANUSCRIPT_FLOOD_BAND"
    #: A real Snort sensor's own alert priority.
    SNORT_PRIORITY = "SNORT_PRIORITY"
    #: AETHRA-SEC's risk engine, from a computed score.
    APPLICATION_SCORE = "APPLICATION_SCORE"
    #: The baseline carried by a detection rule definition.
    RULE_BASELINE = "RULE_BASELINE"
    #: No severity was supplied and none was inferred.
    NOT_SUPPLIED = "NOT_SUPPLIED"

    @property
    def label(self) -> str:
        """Short label for the interface."""
        return {
            SeveritySource.MANUSCRIPT_FLOOD_BAND: "Flood rate band (manuscript §3.9.8)",
            SeveritySource.SNORT_PRIORITY: "Snort priority",
            SeveritySource.APPLICATION_SCORE: "AETHRA-SEC risk score",
            SeveritySource.RULE_BASELINE: "Detection rule baseline",
            SeveritySource.NOT_SUPPLIED: "Not supplied",
        }[self]

    @property
    def is_manuscript_defined(self) -> bool:
        """True only for the §3.9.8 flood band.

        Every other severity in the system is an application or sensor value,
        and code tempted to present one as a study-defined measure has to read
        this and see the answer.
        """
        return self is SeveritySource.MANUSCRIPT_FLOOD_BAND

    @property
    def provenance(self) -> str:
        """One sentence a report can print beside the value."""
        return {
            SeveritySource.MANUSCRIPT_FLOOD_BAND: (
                "Classified by the sustained packet rate recorded in the "
                "detection's evidence, using the manuscript's §3.9.8 bands."
            ),
            SeveritySource.SNORT_PRIORITY: (
                "Mapped from the priority the Snort sensor supplied; traceable "
                "to that sensor's rule set."
            ),
            SeveritySource.APPLICATION_SCORE: (
                "Computed by AETHRA-SEC's risk engine. An application field, "
                "not a measure the study defines."
            ),
            SeveritySource.RULE_BASELINE: (
                "The baseline the detection rule carries. An application "
                "field, not a measure the study defines."
            ),
            SeveritySource.NOT_SUPPLIED: (
                "No severity was supplied by the source and none was inferred."
            ),
        }[self]


#: The severities the IDS Alerts and Threat Incidents modules use.
#:
#: CRITICAL is deliberately absent. It is not part of the detection severity
#: model these two modules present - §3.9.8 defines Low, Medium and High - so
#: nothing produces it and no screen has a cell, filter option or legend entry
#: for it.
#:
#: :class:`~aethra_sec.models.enums.RiskLevel` keeps its own CRITICAL. The
#: vulnerability assessment module has a separate, legitimate model (§3.9.9,
#: CVSS v3.1) - a CRITICAL finding is still a CRITICAL finding.
DETECTION_SEVERITIES: tuple[Severity, ...] = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def is_detection_severity(severity: Severity | str | None) -> bool:
    """True when a value belongs to the IDS/Incident severity model."""
    if severity is None:
        return False
    parsed = Severity.parse(severity, Severity.INFO)
    return parsed in DETECTION_SEVERITIES


def source_for_evidence(
    source: EvidenceSource | str | None, rule_id: str = ""
) -> SeveritySource:
    """Which severity source applies to a record from ``source``.

    Args:
        rule_id: the detection rule, when known. A flood rule's severity is
            the manuscript band; any other PyShark rule's is its baseline.
    """
    if not isinstance(source, EvidenceSource):
        source = EvidenceSource.parse(source, EvidenceSource.SYSTEM)
    if source is EvidenceSource.SNORT:
        return SeveritySource.SNORT_PRIORITY
    if source is EvidenceSource.PYSHARK:
        from aethra_sec.analytics.anomaly_rules import FLOOD_RULES

        if rule_id in FLOOD_RULES:
            return SeveritySource.MANUSCRIPT_FLOOD_BAND
        return SeveritySource.RULE_BASELINE
    return SeveritySource.APPLICATION_SCORE


#: Printed wherever severity is summarised, so a reader is never left to assume
#: where the bands came from.
SEVERITY_DISCLOSURE = (
    "Flood detections (ICMP, UDP, TCP SYN, HTTP) are rated by the manuscript's "
    "§3.9.8 packet-rate bands. Every other severity is not defined by the "
    "study: it comes from a Snort sensor's own alert priority or from "
    "AETHRA-SEC's rule baselines and risk score, and the source is recorded "
    "with each record."
)
