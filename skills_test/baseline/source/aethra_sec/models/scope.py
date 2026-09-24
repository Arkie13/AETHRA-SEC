"""What the manuscript defines as AETHRA-SEC's tested attack scope.

This module exists so that "is this category part of the study?" has exactly
one answer, in one place, that the detection engine, the correlation service,
the interface and the reports all read.

The five primary scenarios
--------------------------
The manuscript defines these attack scenarios for AETHRA-SEC testing, each
executed repeatedly in a controlled and isolated laboratory LAN:

1. Port Scanning
2. TCP SYN Flooding
3. UDP Flooding
4. ICMP Flooding
5. HTTP Flooding / abnormal HTTP traffic

That list is the study's *attack-simulation scope*. It is deliberately not the
same thing as the set of events the software is capable of observing, and the
distinction matters in both directions:

* A term appearing in the manuscript's background, literature review or STRIDE
  threat model is **not** thereby an AETHRA-SEC test scenario. Brute force and
  malware are discussed as context; neither is a simulated scenario, so neither
  is implemented as a detection or mitigation category.
* An event the sensors genuinely observe is **not** discarded merely because it
  is outside the primary five. A host sweep that really happened is real
  evidence. It is recorded, kept and shown - labelled
  :attr:`CategoryScope.OTHER_DETECTED` so it is never counted as one of the
  five, and never presented as manuscript-defined test scope.

Deleting real observations to make the interface match a chapter heading would
be falsifying the record, which is the opposite of what scoping is for.

Severity is not defined here
----------------------------
The manuscript does not establish a severity model for the attack simulations,
so this module does not invent one and does not rank the scenarios. Where
severity comes from, and how much of it is traceable to a real sensor, is
recorded in :mod:`aethra_sec.models.severity_source` instead.
"""

from __future__ import annotations

from aethra_sec.models.enums import StrEnum, ThreatCategory


class CategoryScope(StrEnum):
    """How a threat category relates to the manuscript's tested scope."""

    #: One of the five attack scenarios the manuscript defines and tests.
    PRIMARY = "PRIMARY"
    #: A real security event the sensors can observe and that the system
    #: records, which is *not* one of the five simulated scenarios. Kept as
    #: evidence; never counted as manuscript test scope.
    OTHER_DETECTED = "OTHER_DETECTED"
    #: An observation the system could not attribute to any category.
    UNCLASSIFIED = "UNCLASSIFIED"

    @property
    def label(self) -> str:
        """How the scope is named in the interface."""
        return {
            CategoryScope.PRIMARY: "Tested scenario",
            CategoryScope.OTHER_DETECTED: "Other detected event",
            CategoryScope.UNCLASSIFIED: "Unclassified",
        }[self]

    @property
    def description(self) -> str:
        """One line explaining the scope, for tooltips and report legends."""
        return {
            CategoryScope.PRIMARY: (
                "One of the five attack scenarios the study defines and tests."
            ),
            CategoryScope.OTHER_DETECTED: (
                "A real security event the sensors observed. It is recorded as "
                "evidence but is not one of the study's tested scenarios."
            ),
            CategoryScope.UNCLASSIFIED: (
                "Observed, but not attributable to a category."
            ),
        }[self]


#: The five tested attack scenarios, in the order the manuscript lists them.
#: This tuple is the authority; nothing else in the codebase may define it.
PRIMARY_SCENARIOS: tuple[ThreatCategory, ...] = (
    ThreatCategory.PORT_SCAN,
    ThreatCategory.TCP_SYN_FLOOD,
    ThreatCategory.UDP_FLOOD,
    ThreatCategory.ICMP_FLOOD,
    ThreatCategory.HTTP_FLOOD,
)

#: The manuscript's own wording for each scenario, used in reports so the
#: study's terms appear rather than an internal identifier.
SCENARIO_NAMES: dict[ThreatCategory, str] = {
    ThreatCategory.PORT_SCAN: "Port Scanning",
    ThreatCategory.TCP_SYN_FLOOD: "TCP SYN Flooding",
    ThreatCategory.UDP_FLOOD: "UDP Flooding",
    ThreatCategory.ICMP_FLOOD: "ICMP Flooding",
    ThreatCategory.HTTP_FLOOD: "HTTP Flooding / abnormal HTTP traffic",
}


def scope_of(category: ThreatCategory | str | None) -> CategoryScope:
    """Which scope a category belongs to.

    Args:
        category: a :class:`ThreatCategory`, its stored string, or ``None``.
            A value that is not a known category - a row written before a
            category was retired, say - resolves to
            :attr:`CategoryScope.UNCLASSIFIED` rather than raising, so a
            historical record stays readable.
    """
    if not isinstance(category, ThreatCategory):
        if category is None:
            return CategoryScope.UNCLASSIFIED
        parsed = ThreatCategory.parse(category, ThreatCategory.UNCLASSIFIED)
        category = parsed if isinstance(parsed, ThreatCategory) else None
    if category is None or category is ThreatCategory.UNCLASSIFIED:
        return CategoryScope.UNCLASSIFIED
    if category in PRIMARY_SCENARIOS:
        return CategoryScope.PRIMARY
    return CategoryScope.OTHER_DETECTED


def is_primary(category: ThreatCategory | str | None) -> bool:
    """True when the category is one of the five tested scenarios."""
    return scope_of(category) is CategoryScope.PRIMARY


def scenario_name(category: ThreatCategory | str | None) -> str:
    """The manuscript's name for a tested scenario, else the category label.

    Used where a report or chart should read in the study's own terms. A
    category outside the five keeps its ordinary label - it is not given a
    scenario name it does not have.
    """
    if isinstance(category, str):
        parsed = ThreatCategory.parse(category, ThreatCategory.UNCLASSIFIED)
        category = parsed if isinstance(parsed, ThreatCategory) else None
    if category is None:
        return ThreatCategory.UNCLASSIFIED.label
    return SCENARIO_NAMES.get(category, category.label)
