"""The five attack categories the Attack Statistics page reports, and how
each detection source maps onto them.

Mapped from structured identifiers only - an AETHRA-SEC rule id, or a Snort
(generator, signature, revision) - never from message text. Anything without
an entry here is reported as OTHER rather than guessed into a category.

The Snort entries describe the rule set deployed with this installation
(``deploy/snort/local.rules``). A signature id is only meaningful together
with the rule text it was deployed with: sid 1000002 revision 1 was a "TCP SYN
flood" rule and revision 2 is "TCP SYN (any port)", so the revision is part of
the key and an undeployed revision is OTHER.
"""

from __future__ import annotations

from dataclasses import dataclass

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    RULE_HTTP_FLOOD,
    RULE_ICMP_FLOOD,
    RULE_PORT_SCAN,
    RULE_SYN_FLOOD,
    RULE_UDP_FLOOD,
)

TCP = "TCP"
HTTP = "HTTP"
UDP = "UDP"
ICMP = "ICMP"
PORT_SCAN = "PORT SCAN"
#: Reported, but not one of the five: a host sweep discovers which hosts are
#: alive (often by ARP); it does not probe ports, so it is not a port scan.
HOST_SWEEP = "HOST SWEEP"
OTHER = "OTHER"

#: The five categories, in display order.
CATEGORIES: tuple[str, ...] = (TCP, HTTP, UDP, ICMP, PORT_SCAN)

#: AETHRA-SEC rule -> category. One rule, one category, so an episode (one
#: detection record) is counted in exactly one category.
AETHRA_RULE_CATEGORY: dict[str, str] = {
    RULE_SYN_FLOOD: TCP,
    RULE_HTTP_FLOOD: HTTP,
    RULE_UDP_FLOOD: UDP,
    RULE_ICMP_FLOOD: ICMP,
    RULE_PORT_SCAN: PORT_SCAN,
    RULE_HOST_SWEEP: HOST_SWEEP,
}


@dataclass(frozen=True)
class SnortSignature:
    """What one deployed Snort rule detects."""

    category: str
    #: True for threshold rules that report an attack; False for per-packet
    #: rules that fire on every matching packet (a single ping, a single SYN)
    #: and are evidence, not an attack by themselves.
    is_attack_rule: bool
    rule_text: str


#: (generator, signature, revision) -> meaning, for deploy/snort/local.rules.
SNORT_SIGNATURES: dict[tuple[int, int, int], SnortSignature] = {
    (1, 1000006, 2): SnortSignature(ICMP, True, "ICMP flood - possible ping flood/DoS"),
    (1, 1000007, 2): SnortSignature(TCP, True, "TCP SYN flood - possible DoS"),
    (1, 1000008, 3): SnortSignature(UDP, True, "UDP flood - possible DoS"),
    # Revision 2 is not in the bundled rule files. The deployed file's comment
    # on revision 3 describes it as the same threshold rule with a source
    # exclusion added, and 77 stored rev-2 alerts carry the same message, so
    # it is the same detection. (sid 1000002 rev 1 is NOT mapped: the stored
    # message and the bundled windows/local.rules disagree about what it was.)
    (1, 1000008, 2): SnortSignature(UDP, True, "UDP flood - possible DoS (rev 2)"),
    # A SYN flood aimed at the web port. It counts SYN packets, not HTTP
    # requests, so it is TCP - the same reading the correlation engine uses.
    (1, 1000009, 2): SnortSignature(TCP, True, "HTTP port SYN flood - possible web server DoS"),
    (1, 1000010, 2): SnortSignature(TCP, True, "HTTPS port SYN flood - possible web server DoS"),
    (1, 1000001, 2): SnortSignature(ICMP, False, "ICMP echo request"),
    (1, 1000002, 2): SnortSignature(TCP, False, "TCP SYN (any port)"),
    (1, 1000003, 2): SnortSignature(UDP, False, "UDP traffic to DNS port"),
    (1, 1000004, 2): SnortSignature(TCP, False, "TCP SYN to HTTP port"),
    (1, 1000005, 2): SnortSignature(TCP, False, "TCP SYN to HTTPS port"),
}

#: Categories for which the deployed Snort rule set has an attack rule. For
#: the others Snort cannot report an attack count at all, which the page says.
SNORT_ATTACK_COVERAGE: frozenset[str] = frozenset(
    s.category for s in SNORT_SIGNATURES.values() if s.is_attack_rule
)


def aethra_category(rule_id: str) -> str:
    """Category of an AETHRA-SEC detection, OTHER when the rule is unknown."""
    return AETHRA_RULE_CATEGORY.get(rule_id or "", OTHER)


def snort_signature(generator: int | None, signature: int | None,
                    revision: int | None) -> SnortSignature | None:
    """The deployed meaning of a Snort alert, or None for an unknown rule."""
    try:
        key = (int(generator or 0), int(signature or 0), int(revision or 0))
    except (TypeError, ValueError):
        return None
    return SNORT_SIGNATURES.get(key)


# ----------------------------------------------------------------------------
# The Attack Statistics model - a pure function of the two GROUP BY results
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class CategoryRow:
    """One category's figures. ``None`` means "this source cannot report it"."""

    category: str
    aethra_episodes: int
    aethra_active: int
    correlated: int
    snort_attack_raw: int | None
    snort_attack_records: int | None
    snort_observation_raw: int


@dataclass(frozen=True)
class AttackStatistics:
    rows: tuple[CategoryRow, ...]
    host_sweep_episodes: int
    host_sweep_active: int
    other_aethra_episodes: int
    other_snort_raw: int
    aethra_total: int
    aethra_active: int
    correlated_total: int
    snort_attack_raw_total: int
    snort_observation_raw_total: int
    snort_records_total: int
    legacy_aethra_episodes: int
    latest_detection: object
    unmapped_snort: tuple[tuple[int | None, int | None, int | None], ...]

    @property
    def aethra_ended(self) -> int:
        return self.aethra_total - self.aethra_active


def summarise(aethra: list[dict], snort: list[dict]) -> AttackStatistics:
    """Fold the per-rule and per-signature figures into the page's model.

    Each AETHRA-SEC detection is one episode in exactly one category. Snort
    attack-rule alerts and per-packet observations are kept apart, and neither
    is ever added to an episode count. Correlated counts AETHRA-SEC episodes
    whose attack the correlation engine linked to at least one Snort alert.
    """
    per: dict[str, dict[str, int]] = {
        c: {"episodes": 0, "active": 0, "correlated": 0, "attack_raw": 0,
            "attack_records": 0, "obs_raw": 0}
        for c in (*CATEGORIES, HOST_SWEEP, OTHER)
    }
    legacy = 0
    latest = None
    for row in aethra:
        category = aethra_category(row["rule_id"])
        bucket = per[category]
        bucket["episodes"] += row["episodes"]
        bucket["active"] += row["active"]
        bucket["correlated"] += row["correlated"]
        if category in CATEGORIES:  # the same set aethra_total counts
            legacy += row["episodes"] - row.get("revised", 0)
        if row.get("latest") is not None and (latest is None or row["latest"] > latest):
            latest = row["latest"]
    unmapped = []
    other_snort_raw = 0
    for row in snort:
        meaning = snort_signature(row["generator_id"], row["signature_id"], row["revision"])
        if meaning is None:
            unmapped.append((row["generator_id"], row["signature_id"], row["revision"]))
            other_snort_raw += row["raw_alerts"]
            continue
        bucket = per[meaning.category]
        if meaning.is_attack_rule:
            bucket["attack_raw"] += row["raw_alerts"]
            bucket["attack_records"] += row["records"]
        else:
            bucket["obs_raw"] += row["raw_alerts"]
    rows = tuple(
        CategoryRow(
            category=c,
            aethra_episodes=per[c]["episodes"],
            aethra_active=per[c]["active"],
            correlated=per[c]["correlated"],
            snort_attack_raw=per[c]["attack_raw"] if c in SNORT_ATTACK_COVERAGE else None,
            snort_attack_records=per[c]["attack_records"] if c in SNORT_ATTACK_COVERAGE else None,
            snort_observation_raw=per[c]["obs_raw"],
        )
        for c in CATEGORIES
    )
    return AttackStatistics(
        rows=rows,
        host_sweep_episodes=per[HOST_SWEEP]["episodes"],
        host_sweep_active=per[HOST_SWEEP]["active"],
        other_aethra_episodes=per[OTHER]["episodes"],
        other_snort_raw=other_snort_raw,
        aethra_total=sum(r.aethra_episodes for r in rows),
        aethra_active=sum(r.aethra_active for r in rows),
        correlated_total=sum(r.correlated for r in rows),
        snort_attack_raw_total=sum(r.snort_attack_raw or 0 for r in rows),
        snort_observation_raw_total=sum(r.snort_observation_raw for r in rows),
        snort_records_total=sum(row["records"] for row in snort),
        legacy_aethra_episodes=legacy,
        latest_detection=latest,
        unmapped_snort=tuple(unmapped),
    )
