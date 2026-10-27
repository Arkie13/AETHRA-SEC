"""IDS alert screen (§43, §66).

Lists real Snort alerts with search, filtering, workflow status, analyst
classification, related evidence and mitigation guidance. When no sensor is
connected the screen says so, using the transport's own status text.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk
from typing import Any, Sequence

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.alert import SnortAlert
from aethra_sec.analytics.anomaly_rules import flood_band
from aethra_sec.analytics.episodes import (
    DEFAULT_INACTIVITY_SECONDS,
    EpisodeStatus,
)
from aethra_sec.models.enums import AlertStatus, EvaluationLabel, Severity
from aethra_sec.models.periods import (
    CUSTOM_RANGE,
    NAMED_RANGES,
    DashboardPeriod,
    local_today,
    parse_moment,
    period_for_range,
)
from aethra_sec.models.mitigation import LOOKUP_FAILED_TEXT, MitigationMatch
from aethra_sec.models.severity_source import DETECTION_SEVERITIES
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT
from aethra_sec.ui.guide_text import (
    apply_guide_context,
    guide_context,
    placeholder_note,
    unfilled_placeholders,
)
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget, state_colour
from aethra_sec.core.permissions import Permission
from aethra_sec.ui.widgets import (
    FormDialog,
    FormField,
    Card, Column, DataTable, DetailDialog, DetailSection, FilterBar, RowAction,
    SummaryCell, SummaryStrip, Toolbar, confirm, show_message,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.formatting import format_count, truncate
from aethra_sec.utils.timeutil import format_local, format_local_ms, utcnow

#: Which engine raised a row. Kept out of the visible columns so the label
#: shown to the operator and the value acted on cannot drift apart.
ORIGIN_SNORT = "SNORT"
ORIGIN_AETHRA = "AETHRA"

#: The mark drawn beside an untriaged detection, in the row's own foreground
#: colour - not a severity colour, and not a colour at all as far as the
#: meaning goes. What carries the meaning is its presence and the column it
#: sits in, so the indicator still reads in a monochrome or high-contrast
#: rendering (§12).
#:
#: A fisheye (U+25C9), deliberately not the plain filled dot. The severity
#: glyphs already use every circle: LOW is a filled circle and INFO a hollow
#: one, so a filled dot here would have been the *same character* the row
#: shows two columns to the right for its severity. Review state and severity
#: are different questions and must not share a symbol. It stays in the
#: Geometric Shapes block the other glyphs come from, so font coverage is
#: identical - nothing new has to render for this to appear.
UNREVIEWED_MARK = "◉"

#: Stored in the cell, and what a copy, an export and the quick filter see.
#: The dot is only how it is drawn.
UNREVIEWED_TEXT = "UNREVIEWED"

ALERT_COLUMNS = (
    # Review state, first and narrow. It is deliberately its own column
    # rather than a prefix on the time: the time cell is read as a time, and
    # a dot glued to it would be read as part of it. This column's heading
    # names what the dot means, which is what keeps the indicator from being
    # a colour-only or shape-only signal.
    Column("review", "Review", width=58, anchor="center", marker=UNREVIEWED_MARK),
    Column("time", "Time", width=145),
    # Provenance is a column, not a footnote. A detection from AETHRA-SEC's
    # own rules is not a Snort alert, and an analyst must be able to see
    # which engine said so before acting on it.
    Column("origin", "Detected by", width=105),
    Column("severity", "Severity", width=100, colour_by="severity", glyph=True),
    # What the traffic is doing NOW, beside what the attack reached.
    # ``severity`` is the worst rate validly measured and does not fall, so a
    # flood that has tailed off still reads HIGH there - correct, but it hides
    # the live state. This column carries the band of the most recent
    # measurement, and is blank when there is no rate to classify.
    Column("now", "Now", width=78, colour_by="severity", glyph=True),
    # The number the severity was decided on. Without it the badge is an
    # assertion the operator cannot check, and a cumulative packet count
    # elsewhere on screen reads like a rate and contradicts it.
    Column("rate", "Rate (pps)", width=100, anchor="e"),
    Column("priority", "Prio", width=48, anchor="e"),
    Column("signature", "Signature", width=125),
    Column("message", "Message", width=300, stretch=True),
    Column("protocol", "Proto", width=60),
    Column("source", "Source", width=150),
    Column("destination", "Destination", width=150),
    Column("count", "Seen", width=52, anchor="e"),
    # The episode. "Time" above is the FIRST observation; without these three
    # a recurring attack is indistinguishable from a single event, which is
    # exactly what an operator needs to tell apart.
    Column("last_seen", "Last seen", width=120),
    Column("duration", "Observed for", width=130),
    Column("episode", "Episode", width=96, anchor="center"),
    Column("status", "Status", width=95, colour_by="status"),
    Column("evaluation", "Evaluation", width=120),
)


LOGGER = get_logger("ui.screens.alerts")

#: Severities the strip has a cell for. INFO folds into LOW, which is what the
#: cell's own tooltip promises; anything else is counted apart rather than
#: swept into LOW, so an unrecognised value shows up as a discrepancy instead
#: of quietly inflating a bucket.
_SEVERITY_CELL = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}


def _value(text: Any, absent: str = "Not available") -> str:
    """One stored field, or a plain statement that it was never supplied.

    Nothing here substitutes a plausible value for a missing one: a blank
    field in a security record is evidence about the record.
    """
    rendered = str(text if text is not None else "").strip()
    return rendered or absent


def _stamp(moment: Any, *, precise: bool = False) -> str:
    """A stored timestamp in local time, or that there is none."""
    if not moment:
        return "Not recorded"
    return format_local_ms(moment) if precise else format_local(moment)


# ----------------------------------------------------------------------
# Detection detail - one record, one set of facts
# ----------------------------------------------------------------------
#: Protocols that have no transport ports, so "Not available" would wrongly
#: suggest a port exists and was not captured.
_PORTLESS_PROTOCOLS = ("ICMP", "ICMPV6", "IGMP", "ARP")


def measurement_count(anomaly: Any) -> tuple[int | None, str]:
    """See :meth:`TrafficAnomaly.observation_count` - one definition everywhere."""
    counter = getattr(anomaly, "observation_count", None)
    if callable(counter):
        return counter()
    return None, "unrecoverable"


def _parse_stamp(value: Any) -> Any:
    """A datetime from the stored evidence, which keeps ISO strings."""
    if isinstance(value, datetime) or not value:
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _is_flood(anomaly: Any) -> bool:
    from aethra_sec.analytics.anomaly_rules import FLOOD_RULES

    return str(getattr(anomaly, "rule_id", "")) in FLOOD_RULES


def _rate_unit(anomaly: Any) -> str:
    """The unit of this rule's threshold, observed and latest values.

    A port scan stores distinct ports and a host sweep distinct hosts. Labelling
    those "pps" made a sweep read "threshold of 15 pps ... crossed with 15
    pps" - an alert apparently raised by trivially low traffic. Their packet
    rate is the Rate column, which is a separate stored measurement.
    """
    rule = str(getattr(anomaly, "rule_id", ""))
    if rule.endswith("HTTP-RATE"):
        return "req/s"
    if rule.endswith("HOST-SWEEP"):
        return "hosts"
    if rule.endswith("PORT-SCAN"):
        return "ports"
    return "pps"


def _num(value: Any) -> str:
    """A measured number as stored: no rounding beyond what was recorded."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return _value(value, "Not recorded")
    return f"{number:,.0f}" if number.is_integer() else f"{number:,.1f}"


def _band_text(rate: Any) -> str:
    from aethra_sec.analytics.anomaly_rules import flood_severity

    try:
        measured = float(rate)
    except (TypeError, ValueError):
        return "Not classified"
    if measured <= 0:
        return "Not classified"
    _severity, summary = flood_severity(measured)
    return summary


def _trigger_measurement(anomaly: Any) -> dict[str, Any]:
    """The measurement recorded at the instant the threshold was first crossed.

    It is the evidence stored with the record at insert, which is never
    overwritten - so it is the trigger, not "the observation" of the episode.
    """
    evidence = getattr(anomaly, "evidence", None) or {}
    count = None
    for name in (
        "icmp_packets_in_window", "udp_packets_in_window",
        "syn_packets_in_window", "http_requests_in_window",
    ):
        if name in evidence:
            count = evidence[name]
            break
    window = evidence.get("window_seconds", getattr(anomaly, "window_seconds", None))
    # The rule stores first_seen as the triggering packet's capture time minus
    # the window, so the packet time is recovered exactly. detected_at is when
    # the analysis reached that packet - a different clock, kept separately.
    first_seen = getattr(anomaly, "first_seen", None)
    at = None
    if first_seen is not None and window:
        try:
            at = first_seen + timedelta(seconds=float(window))
        except (TypeError, ValueError):
            at = None
    return {
        "rate": evidence.get("observed_rate_pps"),
        "count": count,
        "window": window,
        "band": evidence.get("severity_band"),
        "at": at,
        "analysed_at": getattr(anomaly, "detected_at", None),
    }


def _capture_statement(snapshot: dict[str, Any] | None) -> str:
    """What the capture counters recorded with one measurement say - and do not.

    The counters are cumulative from the moment capture started, not for this
    episode alone, and they can only see packets that reached this computer.
    A loss of zero used to be presented as "a complete measurement", which the
    counters cannot establish.
    """
    if not snapshot:
        return "Capture state not recorded with this measurement"
    completeness = snapshot.get("capture_completeness")
    offered = snapshot.get("adapter_packets_since_capture_start")
    if completeness is not None:
        try:
            share = float(completeness)
        except (TypeError, ValueError):
            share = None
        if share is not None:
            shown = min(share, 1.0)
            since = (
                f"of the {int(offered):,} packets the adapter counted since capture "
                "began" if offered is not None else "of the packets the adapter counted"
            )
            if share < 0.95:
                return (
                    f"INCOMPLETE - only {shown:.1%} {since} reached the analysis "
                    "(cumulative since capture start, not for this episode alone). "
                    "The measured rate is a lower bound, not the attack rate."
                )
            return (
                f"{shown:.1%} {since} reached the analysis (cumulative). No loss "
                "inside this computer is shown; traffic that never reached the "
                "adapter cannot be counted, so this does not prove every packet "
                "on the network was seen."
            )
    loss = snapshot.get("capture_loss_rate")
    if loss is not None:
        try:
            lost = float(loss)
        except (TypeError, ValueError):
            lost = None
        if lost == 0:
            return (
                "The capture reported 0 dropped packets (cumulative). Packets "
                "that never reached the adapter cannot be counted, so this is "
                "not proof that every packet on the network was seen."
            )
        if lost is not None:
            return (
                f"INCOMPLETE - the capture dropped {lost:.1%} of the packets "
                "offered to it (cumulative); the measured rate is a lower bound."
            )
    return "Capture state not recorded with this measurement"


def _episode_capture(trigger: dict[str, Any], latest: dict[str, Any] | None) -> str:
    """Capture completeness over the episode itself, from two real snapshots."""
    if not latest:
        return "Needs a second measurement - not available for this episode"
    try:
        seen = int(latest["capture_packets_seen"]) - int(trigger["capture_packets_seen"])
        offered = (
            int(latest["adapter_packets_since_capture_start"])
            - int(trigger["adapter_packets_since_capture_start"])
        )
    except (KeyError, TypeError, ValueError):
        return "Not recorded for this episode"
    if offered <= 0:
        return "Not computable - the adapter counter did not advance"
    share = seen / offered
    note = (
        " (above 100% because the two counters are sampled a moment apart)"
        if share > 1 else ""
    )
    verdict = "INCOMPLETE - the rates are lower bounds. " if share < 0.95 else ""
    return (
        f"{verdict}Between the trigger and the latest measurement the adapter "
        f"counted {offered:,} packets and {seen:,} ({share:.1%}) reached the "
        f"analysis{note}."
    )


def _measurement_line(
    rate: Any, count: Any, window: Any, at: Any, unit: str
) -> str:
    parts = [f"{_num(rate)} {unit}"]
    if count is not None and window:
        parts.append(f"= {int(count):,} counted in {window} s")
    if at:
        parts.append(f"at {_stamp(_parse_stamp(at), precise=True)}")
    return " ".join(parts)


def _episode_narrative(anomaly: Any) -> str:
    """The observation, generated from this record's own measurements.

    The stored ``observation`` sentence is written once, when the threshold is
    first crossed - at which instant the count is necessarily AT the threshold
    (600 ICMP packets in 5 s is exactly 120 pps). It was shown as "the
    observation" of the whole episode, so a flood measured at 1,040.2 pps read
    as "120 packets/second ... Low". It is still shown, labelled as what it is.
    """
    unit = _rate_unit(anomaly)
    source = _value(getattr(anomaly, "src_ip", ""), "an unrecorded source")
    target = getattr(anomaly, "dst_ip", "") or ""
    evidence = getattr(anomaly, "evidence", None) or {}
    trigger = _trigger_measurement(anomaly)
    latest = evidence.get("latest_measurement") or {}
    peak = evidence.get("peak_measurement") or {}
    window = getattr(anomaly, "window_seconds", None) or trigger["window"]
    threshold = getattr(anomaly, "threshold_value", None)
    lines = [
        f"{source}{' -> ' + target if target else ''}: the alert threshold of "
        f"{_num(threshold)} {unit} over {window} s was crossed "
        f"{('at ' + _stamp(trigger['at'], precise=True)) if trigger['at'] else ''}"
        f"{' with ' + _num(trigger['rate']) + ' ' + unit if trigger['rate'] is not None else ''}."
        " Crossing it makes traffic a detection; it does not set the severity.",
    ]
    if getattr(anomaly, "latest_value", None) is not None:
        lines.append(
            f"Latest measurement: "
            + _measurement_line(
                anomaly.latest_value, latest.get("packets_in_window"), window,
                latest.get("measured_at") or getattr(anomaly, "latest_measured_at", None),
                unit,
            )
            + (f" - severity band {_band_text(anomaly.latest_value)}." if _is_flood(anomaly) else ".")
        )
    else:
        lines.append("No later measurement was folded into this episode; the "
                     "trigger measurement is the only one.")
    lines.append(
        f"Peak measurement: "
        + _measurement_line(
            anomaly.observed_value, peak.get("packets_in_window"), window,
            peak.get("measured_at"), unit,
        )
        + (f" - severity band {_band_text(anomaly.observed_value)}." if _is_flood(anomaly) else ".")
    )
    return "\n".join(lines)


def _anomaly_detail_sections(
    anomaly: Any, when: Any, episode: Any
) -> list["DetailSection"]:
    """Detection information, episode, network and evidence for ONE record.

    Every value is read from ``anomaly`` - its columns and its own evidence -
    and nothing else. Where the record does not hold a value, the row says so.
    """
    from aethra_sec.analytics.anomaly_rules import FLOOD_BANDS

    evidence = getattr(anomaly, "evidence", None) or {}
    flood = _is_flood(anomaly)
    unit = _rate_unit(anomaly)
    trigger = _trigger_measurement(anomaly)
    latest = evidence.get("latest_measurement") or None
    peak = evidence.get("peak_measurement") or None
    protocol = (anomaly.protocol or "").upper()
    portless = protocol in _PORTLESS_PROTOCOLS
    not_applicable = f"Not applicable - {protocol or 'this protocol'} has no ports"
    has_latest = anomaly.latest_value is not None
    # Which engine recorded this row decides what its numbers mean. Rows from
    # before the 15 Oct 2026 revision carry no ``measurement_scope``: their
    # ICMP count could include echo replies, and their latest measurement time
    # is the analysis clock. They are described as they were recorded.
    revised = "measurement_scope" in evidence
    if not flood:
        direction = "As recorded by the rule"
    elif revised or protocol not in ("ICMP", "ICMPV6"):
        direction = (
            "Source -> destination only. Echo replies answering the "
            "destination's own requests are not counted."
            if protocol in ("ICMP", "ICMPV6") else "Source -> destination only"
        )
    else:
        direction = (
            "Packets sent by the source. Recorded before the 15 Oct 2026 revision, when "
            "echo replies were still counted: if this source was the TARGET of "
            "a ping flood, these are its replies, not an attack."
        )
    latest_at = (latest or {}).get("measured_at")
    latest_clock = "" if latest_at or evidence.get("measurement_clock") == "packet" else (
        " (analysis time - recorded before measurement times used the packet clock)"
        if anomaly.latest_measured_at else ""
    )

    count, basis = measurement_count(anomaly)
    if basis == "counted":
        measurements_text = (
            f"{count:,} - observations folded into this record (the first "
            "detection plus each later measurement). Not a packet count and "
            "not a count of attacks."
        )
    elif basis == "derived":
        measurements_text = (
            f"{count:,} - derived exactly from the stored count "
            f"{anomaly.event_count:,}, which on records before the 15 Oct 2026 "
            "revision started at the trigger rate instead of 1. Not a packet count."
        )
    else:
        measurements_text = (
            f"Not recoverable - the stored count {anomaly.event_count:,} started "
            "at the rule's measured value on records before the 15 Oct 2026 "
            "revision, and that value is not stored for this rule."
        )

    if flood and has_latest:
        current = (
            f"{anomaly.current_severity} - from the latest measurement, "
            f"{_num(anomaly.latest_value)} {unit}"
        )
    elif flood:
        current = f"{anomaly.current_severity} - only the trigger measurement exists"
    else:
        current = (
            f"{anomaly.current_severity} - graded on the rule's own measure, "
            "not a latest rate"
        )

    return [
        DetailSection(
            "DETECTION INFORMATION",
            rows=[
                ("Detection ID", _value(anomaly.id)),
                ("Title", _value(anomaly.title)),
                ("Rule", _value(anomaly.rule_id)),
                ("Category", _value(anomaly.category)),
                ("Protocol", _value(anomaly.protocol)),
                ("Detected by", "AETHRA-SEC traffic rules"),
                ("Evidence source", _value(anomaly.source)),
                ("First detected", _stamp(when, precise=True)),
                ("Current severity", current),
                (
                    "Peak severity",
                    f"{anomaly.highest_severity} - from the peak, "
                    f"{_num(anomaly.observed_value)} {unit}"
                    if flood else str(anomaly.highest_severity),
                ),
                (
                    "Episode severity",
                    f"{anomaly.episode_severity} - the worst this episode reached; "
                    "it never falls. The badge, counters, filters and "
                    "notifications use this value.",
                ),
                (
                    "Alert trigger",
                    f"{_num(anomaly.threshold_value)} {unit} sustained over "
                    f"{anomaly.window_seconds} s. Reaching it raises the "
                    "detection; it does not decide the severity."
                    if flood else
                    f"{_num(anomaly.threshold_value)} over {anomaly.window_seconds} s",
                ),
                (
                    "Severity bands",
                    "; ".join(band.summary() for band in FLOOD_BANDS)
                    + " - applied to the measured rate"
                    if flood else "Not a rate rule - see the observation",
                ),
                (
                    "Confidence",
                    f"{anomaly.confidence}%" if anomaly.confidence else "Not recorded",
                ),
            ],
        ),
        DetailSection(
            "OBSERVED EPISODE",
            rows=[
                ("First seen", _stamp(anomaly.first_observed, precise=True)),
                ("Last seen", _stamp(anomaly.last_observed, precise=True)),
                ("Observed duration", episode.duration_text),
                ("Episode status", episode.status.label),
                ("What that means", episode.status.explanation),
                ("Measurements in episode", measurements_text),
                (
                    "Latest measurement",
                    _measurement_line(
                        anomaly.latest_value,
                        (latest or {}).get("packets_in_window"),
                        anomaly.window_seconds,
                        (latest or {}).get("measured_at") or anomaly.latest_measured_at,
                        unit,
                    ) + latest_clock if has_latest else "Only the trigger measurement exists",
                ),
                (
                    "Peak measurement",
                    _measurement_line(
                        anomaly.observed_value,
                        (peak or {}).get("packets_in_window"),
                        anomaly.window_seconds,
                        (peak or {}).get("measured_at"), unit,
                    ),
                ),
                (
                    "Trigger measurement",
                    _measurement_line(
                        trigger["rate"], trigger["count"], trigger["window"],
                        trigger["at"], unit,
                    ) if trigger["rate"] is not None else "Not recorded",
                ),
                (
                    "Average rate",
                    "Not calculated - the record stores individual window "
                    "measurements, not the episode's total packet count",
                ),
                (
                    "Total packets in episode",
                    "Not recorded - each measurement counts one "
                    f"{anomaly.window_seconds} s window only",
                ),
                (
                    "Analysis lag at latest measurement",
                    f"{float(latest['analysis_lag_seconds']):.1f} s between the "
                    "packets' capture time and their analysis"
                    if latest and latest.get("analysis_lag_seconds") is not None
                    else "Not recorded",
                ),
                (
                    "Note",
                    "The duration is the span between the first and last "
                    "observation. It does not assert that traffic was "
                    "continuously present throughout, and a gap in "
                    "observations is not evidence the activity stopped. "
                    "This is not detection time (section 3.9.2), which "
                    "needs a separately recorded attack-initiation "
                    "timestamp.",
                ),
            ],
        ),
        DetailSection(
            "NETWORK DETAILS",
            rows=[
                ("Protocol", _value(anomaly.protocol)),
                ("Source IP", _value(anomaly.src_ip)),
                ("Destination IP", _value(anomaly.dst_ip)),
                (
                    "Source port",
                    not_applicable if portless
                    else "Not recorded - the rule tracks the source address",
                ),
                (
                    "Destination port",
                    not_applicable if portless
                    else _value(anomaly.dst_port, "Not recorded"),
                ),
                ("Interface", _value(anomaly.interface)),
                ("Direction measured", direction),
                (
                    "Measurement scope",
                    _value(evidence.get("rate_scope"),
                           "Scope not recorded for this detection"),
                ),
                (
                    "Correlated attack",
                    f"#{int(anomaly.incident_id)} - detections of the same "
                    "attack are grouped under this number ('One row per "
                    "attack' view)"
                    if anomaly.incident_id else "Not yet correlated",
                ),
            ],
        ),
        DetailSection(
            "EVIDENCE",
            rows=[
                ("Evidence source", _value(anomaly.source)),
                ("Evidence record", f"traffic_anomalies #{_value(anomaly.id)}"),
                ("Measurement window", f"{_value(anomaly.window_seconds)} s"),
                ("Capture at trigger", _capture_statement(evidence)),
                (
                    "Capture at latest measurement",
                    _capture_statement(latest) if latest
                    else "Not recorded for this measurement",
                ),
                ("Capture over this episode", _episode_capture(evidence, latest)),
                (
                    "Severity input",
                    f"Current: latest rate {_num(anomaly.latest_value)} {unit}; "
                    f"peak: {_num(anomaly.observed_value)} {unit}"
                    if flood and has_latest
                    else f"Trigger/peak rate {_num(anomaly.observed_value)} {unit}"
                    if flood else "The rule's own measure (see the observation)",
                ),
            ],
            body="\n\n".join(
                f"{label}\n{_value(text, 'Not recorded')}"
                for label, text in (
                    ("Observation", _episode_narrative(anomaly)),
                    (
                        "Trigger observation (recorded when the threshold was "
                        "first crossed; not updated afterwards)",
                        anomaly.observation,
                    ),
                    ("Why it matters", anomaly.why_it_matters),
                    ("What to check", anomaly.what_to_check),
                )
            ),
        ),
    ]


#: The Alerts view choices. "Each detection" is every raw sensor record, as
#: before; "One row per attack" collapses detections the correlation engine
#: bound to one attack into a single primary row.
#: Which records the table lists. AETHRA-SEC's own detections are the primary
#: alerts; Snort's are supporting evidence, kept and inspectable on their own.
SOURCE_AETHRA = "AETHRA-SEC detections"
SOURCE_SNORT = "Snort evidence (raw alerts)"

VIEW_EACH_DETECTION = "Each detection"
VIEW_ONE_PER_ATTACK = "One row per attack"


def _row_rank(row: dict[str, Any]) -> tuple[int, int, Any]:
    """Primary-row preference inside one attack.

    AETHRA-SEC's own detection first - it carries the measured rate and the
    episode - then the highest severity, then the newest.
    """
    try:
        rank = Severity(str(row.get("severity", "")).upper()).rank
    except ValueError:
        rank = -1
    return (1 if row.get("_origin") == ORIGIN_AETHRA else 0, rank, row.get("_sort"))


def one_row_per_attack(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[tuple[str, Any], list[dict[str, Any]]]]:
    """Collapse rows that belong to the same correlated attack.

    Rows carry ``_attack`` - the correlation record the engine bound them to,
    which already requires the same protocol family, source and destination
    inside the correlation window. Rows with no ``_attack`` have not been
    correlated yet and stay as rows of their own; nothing is merged on title
    or signature similarity.

    Returns the primary rows, and for each primary ``(origin, id)`` every
    row of its attack (primary included) so the detail view can list the
    supporting evidence. No row is dropped from the data - only from the
    table in this view.
    """
    groups: dict[Any, list[dict[str, Any]]] = {}
    singles: list[dict[str, Any]] = []
    for row in rows:
        attack = row.get("_attack")
        if attack is None:
            singles.append(row)
        else:
            groups.setdefault(attack, []).append(row)

    primaries: list[dict[str, Any]] = list(singles)
    members: dict[tuple[str, Any], list[dict[str, Any]]] = {}
    for group in groups.values():
        primary = max(group, key=_row_rank)
        others = [row for row in group if row is not primary]
        shown = dict(primary)
        if others:
            snort = sum(1 for row in others if row.get("_origin") != ORIGIN_AETHRA)
            aethra = len(others) - snort
            parts = []
            if aethra:
                parts.append(f"{aethra} AETHRA-SEC")
            if snort:
                parts.append(f"{snort} Snort")
            shown["message"] = (
                f"{primary.get('message', '-')} · +{len(others)} related "
                f"({', '.join(parts)})"
            )
        primaries.append(shown)
        members[(primary.get("_origin"), primary.get("_id"))] = group
    primaries.sort(key=lambda row: row["_sort"], reverse=True)
    return primaries, members


def _related_section(group: list[dict[str, Any]] | None, origin: str, ident: Any):
    """The other detections of the same attack, as supporting evidence."""
    if not group or len(group) < 2:
        return None
    lines = []
    for row in sorted(group, key=lambda r: r["_sort"]):
        if row.get("_origin") == origin and row.get("_id") == ident:
            continue
        lines.append(
            f"{row.get('time', '-')}  {row.get('origin', '-'):<10} "
            f"{row.get('severity', '-'):<6} {row.get('signature', '-')}  "
            f"{row.get('message', '-')}  {row.get('source', '-')} -> "
            f"{row.get('destination', '-')}  seen {row.get('count', '-')}"
        )
    return DetailSection(
        "SAME ATTACK - SUPPORTING EVIDENCE",
        body=(
            f"{len(lines)} other detection(s) were correlated with this one as "
            "a single attack (same protocol family, source and destination, "
            "inside the correlation window). Each is still a separate record "
            "with its own evidence; open it from 'Each detection' view.\n\n"
            + "\n".join(lines)
        ),
    )


def snort_evidence_section(anomaly: Any, evidence: Any) -> "DetailSection":
    """Snort alerts linked to this detection's attack, summarised then listed.

    Linked by the correlation engine (same protocol family, source and target,
    active within the episode gap) - never by a timestamp coincidence. Records
    are stored rows; raw alerts include every repeat Snort folded into them.
    """
    heading = "SNORT SUPPORTING EVIDENCE"
    if isinstance(evidence, Exception):
        return DetailSection(heading, body=f"Could not load the Snort evidence: {evidence}")
    if not anomaly.incident_id:
        return DetailSection(
            heading,
            body="Not yet correlated - the correlation engine runs every few "
            "seconds; reopen this detection to see linked Snort alerts.",
        )
    alerts = list(evidence or [])
    if not alerts:
        return DetailSection(
            heading,
            body="No Snort alert is linked to this attack. AETHRA-SEC detected it "
            "on its own; Snort either had no matching rule or raised nothing.",
        )
    raw = sum(int(getattr(a, "duplicate_count", 1) or 1) for a in alerts)
    ports = {a.dst_port for a in alerts if getattr(a, "dst_port", None) is not None}
    signatures: dict[str, int] = {}
    for alert in alerts:
        key = f"[{alert.generator_id}:{alert.signature_id}:{alert.revision}] {alert.message}"
        signatures[key] = signatures.get(key, 0) + int(alert.duplicate_count or 1)
    times = [a.effective_time for a in alerts if a.effective_time]
    rows = [
        ("Snort records linked", f"{len(alerts):,}" + (" (newest 200 shown)" if len(alerts) >= 200 else "")),
        ("Raw Snort alerts", f"{raw:,} - each alert line Snort wrote, repeats included"),
        ("Distinct destination ports", f"{len(ports):,}" if ports else "None recorded"),
        ("First / last Snort alert",
         f"{_stamp(min(times), precise=True)} / {_stamp(max(times), precise=True)}"
         if times else "Not recorded"),
    ]
    body = "Signatures (raw alerts):\n" + "\n".join(
        f"  {count:>8,}  {name}" for name, count in sorted(signatures.items(), key=lambda kv: -kv[1])
    )
    return DetailSection(heading, rows=rows, body=body)


def _rule_text(alert: SnortAlert) -> str:
    """The sensor's own rule identity, naming each part it did not supply."""
    parts = []
    for label, number in (
        ("GID", alert.generator_id),
        ("SID", alert.signature_id),
        ("Rev", alert.revision),
    ):
        parts.append(f"{label} {number}" if number is not None else f"{label} not supplied")
    return " · ".join(parts)


def _detected_by(alert: SnortAlert) -> str:
    """Which sensor reported this, as the record itself states it."""
    sensor = str(alert.sensor or "").strip()
    return f"Snort ({sensor})" if sensor else "Snort"


def _detail_status(match: MitigationMatch | None) -> str:
    """The one-line status bar message for an opened detection."""
    if match is None:
        return "Detection opened. The mitigation service is not available."
    if match.lookup_failed:
        return "Detection opened. The mitigation knowledge base could not be read."
    if match.recommendation is None:
        return (
            f"Detection opened. No mitigation entry is mapped to "
            f"{match.category}."
        )
    return (
        f"Detection opened. Mitigation {match.recommendation.code} is mapped to "
        f"{match.category}."
    )


def _selection_note(lines: Sequence[str]) -> str:
    """The "how this was selected" paragraph, omitted when there is nothing to say."""
    if not lines:
        return ""
    return "\n\nHow this entry was selected\n" + "\n".join(lines)



# The filling itself lives in aethra_sec.ui.guide_text, because the
# Mitigation screen and the Vulnerability Assessment drawer show the same
# stored procedures against different kinds of record. These names are kept
# so this module reads as it did.
_guide_context = guide_context
_apply_guide_context = apply_guide_context
_unfilled_placeholders = unfilled_placeholders


#: Rules whose detector stores a packets-per-second figure of its own. That
#: figure is uncapped and is what the severity was taken from, so it is shown
#: as-is. Every other detection - HTTP flood (stored as requests/s), port scan
#: (ports), host sweep (hosts), Snort (signature) - has its packet rate
#: measured from captured traffic instead, so the column is pps for every row.
_STORED_PPS_RULES = frozenset({"RULE-ICMP-RATE", "RULE-UDP-RATE", "RULE-TCP-SYN-RATE"})

#: How many recent detections to measure a packet rate for per load. Bounds the
#: worker's query count; older detections' rows have been pruned and would
#: measure to nothing anyway.
_RATE_MEASURE_LIMIT = 150


def _format_pps(measured: float | None) -> str:
    """A packets-per-second figure for the Rate column, or "-" when unmeasured.

    "-" means no packet from the source was retained to measure - never a real
    zero.
    """
    if measured is None:
        return "-"
    try:
        value = float(measured)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    return f"{value:,.1f}"


def _measured_rate(anomaly: Any, measured: float | None = None) -> str:
    """Packets per second for this detection, so an attack can be tracked.

    The ICMP, UDP and TCP-SYN flood rules store their own packet rate, and the
    peak is shown - one number, because that is the figure the severity was
    taken from. (The live, possibly lower rate is what the Now column bands.)
    Every other rule stores something that is not a packet rate, so the rate
    measured from captured traffic is shown instead, passed in as ``measured``.

    The column is volume only. A port scan or host sweep is classified on
    ports or hosts touched, so a low rate beside a MEDIUM severity is expected
    and correct; the figure is never adjusted to match the severity.
    """
    if str(getattr(anomaly, "rule_id", "")) not in _STORED_PPS_RULES:
        # A port scan or host sweep graded on the pps legend carries the very
        # rate it was graded on; show that, so the number and the severity
        # beside it always agree. Older rows have none and fall back to the
        # rate measured from captured traffic.
        recorded = (getattr(anomaly, "evidence", None) or {}).get(
            "packets_per_second"
        )
        if recorded is not None:
            return _format_pps(recorded)
        return _format_pps(measured)
    return _format_pps(getattr(anomaly, "observed_value", None))


def _measure_rates(
    dashboard: Any,
    alerts: list[Any],
    anomalies: list[Any],
) -> dict[tuple[str, int], float]:
    """Measure packets/second for detections without a stored packet rate.

    Runs on the worker, never the Tk thread. One-directional - packets the
    detection's source sent over the detection's own window - so a target's
    replies are never counted as the attacker's. Bounded by
    ``_RATE_MEASURE_LIMIT`` per source so a full page is not a thousand queries.
    """
    from datetime import timedelta

    rates: dict[tuple[str, int], float] = {}
    if dashboard is None:
        return rates

    def _anchor(item: Any) -> Any:
        return (
            getattr(item, "last_seen", None)
            or getattr(item, "detected_at", None)
            or getattr(item, "created_at", None)
        )

    def _measure(src: Any, end: Any, seconds: float, dst: Any) -> float | None:
        try:
            return dashboard.measured_source_rate(
                src, end - timedelta(seconds=seconds), end, dst_ip=dst or None
            )
        except Exception:  # noqa: BLE001 - a measurement must never break a load
            return None

    pending = [
        a for a in anomalies
        if a.id is not None
        and str(a.rule_id) not in _STORED_PPS_RULES
        # Graded detections already carry their rate; only older rows need one.
        and "packets_per_second" not in (getattr(a, "evidence", None) or {})
        and getattr(a, "src_ip", None)
        and _anchor(a) is not None
    ]
    pending.sort(key=_anchor, reverse=True)
    for anomaly in pending[:_RATE_MEASURE_LIMIT]:
        rate = _measure(
            anomaly.src_ip,
            _anchor(anomaly),
            getattr(anomaly, "window_seconds", None) or 10,
            getattr(anomaly, "dst_ip", None),
        )
        if rate is not None:
            rates[(ORIGIN_AETHRA, anomaly.id)] = rate

    snort_pending = [
        a for a in alerts
        if a.id is not None
        # A Snort alert graded on the pps legend carries its own peak_pps.
        and getattr(a, "peak_pps", None) is None
        and getattr(a, "src_ip", None)
        and getattr(a, "effective_time", None) is not None
    ]
    snort_pending.sort(key=lambda a: a.effective_time, reverse=True)
    for alert in snort_pending[:_RATE_MEASURE_LIMIT]:
        # Snort stamps to the whole second, so a flood whose first packet lands
        # at :22.436 sits AFTER an alert stamped :22.000. A window ending at the
        # stamp misses the attack entirely; measure across the alert's own
        # episode instead - first second through the end of the last - with a
        # floor so a one-off alert still gets a usable window.
        first = getattr(alert, "first_observed", None) or alert.effective_time
        last = getattr(alert, "last_observed", None) or first
        end = max(last, first) + timedelta(seconds=1)
        seconds = max((end - first).total_seconds(), 5.0)
        rate = _measure(
            alert.src_ip, first + timedelta(seconds=seconds), seconds,
            getattr(alert, "dst_ip", None),
        )
        if rate is not None:
            rates[(ORIGIN_SNORT, alert.id)] = rate
    return rates


def _current_band(anomaly: Any) -> str:
    """The band the most recent measurement falls into, or "-" if there is none.

    Only the flood rules classify by packet rate. A port scan's severity is
    measured in distinct ports and a host sweep's in distinct hosts, so
    neither has a rate to put in a band, and this returns "-" rather than
    pushing those numbers through thresholds that do not describe them.
    """
    from aethra_sec.analytics.anomaly_rules import FLOOD_RULES, flood_severity

    if str(getattr(anomaly, "rule_id", "")) not in FLOOD_RULES:
        return "-"
    rate = getattr(anomaly, "latest_value", None)
    if rate is None:
        return "-"
    try:
        measured = float(rate)
    except (TypeError, ValueError):
        return "-"
    if measured <= 0:
        return "-"
    band, _summary = flood_severity(measured)
    return str(band)


def _source_silence_note(snort: Any) -> str:
    """How long the alert source has been silent, when that is knowable.

    "RUNNING" on this screen means the transport is connected, not that the
    sensor is producing anything - and a file nobody writes tails perfectly
    for ever. Saying how old the source is turns an invisible dead feed into
    something an operator can see.
    """
    transport = getattr(snort, "_transport", None)
    age_of = getattr(transport, "source_age_seconds", None)
    if not callable(age_of):
        return ""
    try:
        age = age_of()
    except Exception:  # noqa: BLE001 - a diagnostic is never worth a crash
        return ""
    if age is None:
        return ""
    if age < 300:
        return f" · source written {int(age)}s ago"
    hours, remainder = divmod(int(age), 3600)
    minutes = remainder // 60
    span = f"{hours}h {minutes}m" if hours else f"{minutes}m"
    return (
        f" · NO NEW ALERTS FOR {span} - the file is being tailed correctly; "
        "nothing is writing to it"
    )


def _mitigation_section(
    match: MitigationMatch | None, detection: Any = None
) -> DetailSection:
    """Render the mitigation block for one resolved detection.

    Three outcomes, kept apart on purpose. Guidance that exists is shown with
    the mapping that produced it, so an analyst can check the reasoning rather
    than trust it. A category nobody has written guidance for says exactly
    that. A knowledge base that could not be read says *that*, because
    reporting a fault as "nothing is configured" would tell the operator
    something untrue about their own system.

    No text is composed here. Every line is either a stored knowledge-base
    field or a statement about the lookup.
    """
    if match is None:
        return DetailSection(
            "MITIGATION RECOMMENDATION",
            body=(
                "The mitigation service is not available in this session, so "
                "no lookup was attempted. This is not a statement that the "
                "detection has no guidance."
            ),
            tone="warn",
        )
    if match.lookup_failed:
        detail = match.failure_detail.strip()
        return DetailSection(
            "MITIGATION RECOMMENDATION",
            rows=[("Status", match.status_text)],
            body=LOOKUP_FAILED_TEXT + (f"\n\nRecorded error: {detail}" if detail else ""),
            tone="warn",
        )
    if match.recommendation is None:
        return DetailSection(
            "MITIGATION RECOMMENDATION",
            rows=[
                ("Threat category", str(match.category)),
                ("Status", match.status_text),
            ],
            body=(
                "No mapped mitigation recommendation available for this "
                f"detection.\n\n{NO_RECOMMENDATION_TEXT}\n\n"
                + "\n".join(match.mapping_lines())
            ),
            tone="warn",
        )

    entry = match.recommendation
    context = _guide_context(detection) if detection is not None else {}

    def filled(text: str) -> str:
        return _apply_guide_context(str(text or ""), context)

    procedure = filled(getattr(entry, "procedure_steps", ""))
    verification = filled(entry.verification_steps)
    rollback = filled(getattr(entry, "rollback_steps", ""))

    # Across every part, not just the procedure: a host sweep records no
    # destination, so <TARGET_IP> survives into the verification steps, and
    # a placeholder the operator cannot account for is worse than none.
    outstanding: list[str] = []
    for part in (filled(getattr(entry, "enforcement_point", "")), procedure,
                 verification, rollback,
                 filled(getattr(entry, "operational_warnings", ""))):
        for placeholder in _unfilled_placeholders(part):
            if placeholder not in outstanding:
                outstanding.append(placeholder)

    # Named, not hidden. The operator has to supply these before the
    # commands can be run, and saying so is the whole point.
    note = placeholder_note(outstanding)
    missing_note = f"\n\n{note}" if note else ""

    body_parts = [
        ("Recommendation", entry.threat_name),
        ("What was observed", filled(entry.explanation)),
        ("Why it matters", filled(entry.why_it_matters)),
        ("Where to make the change",
         filled(getattr(entry, "enforcement_point", ""))),
        ("Recommended immediate action", filled(entry.immediate_action)),
        ("Step-by-step procedure", procedure + missing_note),
        ("Verification", verification),
        ("How to undo this change", rollback),
        ("Operational risks and warnings",
         filled(getattr(entry, "operational_warnings", ""))),
        ("Recommended long-term action", filled(entry.long_term_action)),
        ("References", entry.references),
    ]
    body = "\n\n".join(
        f"{label}\n{str(text).strip()}"
        for label, text in body_parts
        if str(text or "").strip()
    )
    return DetailSection(
        "MITIGATION RECOMMENDATION",
        rows=[
            ("Entry", f"{entry.code} - {entry.threat_name}"),
            ("Threat category", str(match.category)),
            ("Applies to service", entry.applies_to_service or "any"),
            ("Knowledge-base status", entry.status_text),
            ("Source / mapping", match.mapping_lines()[0]),
        ],
        body=(
            body
            # The first mapping line is already shown as the "Source /
            # mapping" row above, so only the reasoning follows here.
            + _selection_note(match.mapping_lines()[1:])
            + "\n\nAETHRA-SEC recommends only. It never blocks an address, "
            "changes a firewall rule, stops a service or locks an account - "
            "the authorised operator decides."
        ),
        tone="action",
    )


def _is_unreviewed(detection: Any) -> bool:
    """True when nobody has looked at this detection yet.

    The two sources record it differently: a Snort alert sits in the NEW status
    until an analyst moves it, while one of AETHRA-SEC's own detections carries
    no ``reviewed_at`` stamp until one is marked. Both mean the same thing to
    the operator reading the counter.

    Either kind of attention counts. Classifying a detection plainly means an
    analyst looked at it, so a verdict clears the counter as surely as the
    receipt does; but only the receipt is ever written in bulk, because the
    evaluation labels feed the detection-accuracy statistics and must stay an
    analyst's own judgement.
    """
    status = getattr(detection, "status", None)
    if status is not None:
        return str(status).upper() == "NEW"
    if getattr(detection, "reviewed_at", None) is not None:
        return False
    return str(getattr(detection, "evaluation", "")).upper() in ("", "UNCLASSIFIED")


def _review_cell(detection: Any) -> str:
    """The Review column's stored value for one detection.

    One line, but it is the whole point of the indicator: the cell is decided
    by :func:`_is_unreviewed` reading the record's own persisted review state,
    which is the same predicate ``count_unreviewed_matching`` expresses in
    SQL for the UNREVIEWED counter. The row mark and the count therefore
    cannot disagree - they are two renderings of one fact about the same
    stored row, keyed to the detection rather than to its position in the
    table, so sorting and filtering carry it with the right alert.
    """
    return UNREVIEWED_TEXT if _is_unreviewed(detection) else ""


def _review_status_text(detection: Any) -> str:
    """UNREVIEWED or REVIEWED for the full detection view (§14).

    The same predicate the row mark uses, so the detail cannot contradict the
    table it was opened from.
    """
    return UNREVIEWED_TEXT if _is_unreviewed(detection) else "REVIEWED"


def _summary_cells(totals: dict[str, int]) -> dict[str, int]:
    """Map database severity totals onto the summary strip's cells.

    A severity the strip has no cell for is logged rather than folded into
    LOW, so an unexpected value shows up as a gap instead of a wrong number.
    """
    cells = {"high": 0, "medium": 0, "low": 0, "unreviewed": 0}
    unknown: list[str] = []
    for severity, count in totals.items():
        if severity in ("total", "unreviewed"):
            continue
        cell = _SEVERITY_CELL.get(severity.upper())
        if cell is None:
            unknown.append(severity or "(empty)")
        else:
            cells[cell] += int(count)
    cells["unreviewed"] = int(totals.get("unreviewed", 0))
    if unknown:
        LOGGER.warning(
            "%d severity value(s) have no cell in the summary strip: %s",
            len(unknown), sorted(set(unknown)),
        )
    return cells




#: Default of ``detection.episode_gap_seconds`` (config/defaults.py).
EPISODE_GAP_DEFAULT = 15


def _episode_timeout(screen: Any) -> int:
    """The configured inactivity timeout, in seconds.

    Takes the screen rather than being a method on it: the row builders are
    exercised in the tests by calling them unbound, with ``self`` as ``None``,
    so a Tk screen need not be constructed. The timeout is settings state, not
    screen state, so nothing is lost by reading it through a plain function
    that copes with having no screen.
    """
    try:
        # The same boundary the detector uses to end an episode, so a row
        # cannot read Ongoing after a new episode of the same attack opened.
        return int(screen.context.settings.get_int(
            "detection.episode_gap_seconds", EPISODE_GAP_DEFAULT,
        ))
    except Exception:  # noqa: BLE001 - unbound, or settings unavailable
        return EPISODE_GAP_DEFAULT

def _episode_cells(record: Any, inactivity: int) -> dict[str, Any]:
    """The three episode cells for a detection row.

    A record with one observation shows an em dash for last-seen rather than
    repeating its own timestamp, so the table never implies a span that was
    not observed. A missing last-observed time shows the same dash and the
    status reads Unknown - neither is filled in from the first timestamp.
    """
    episode = record.episode(inactivity_seconds=inactivity)
    if episode.last_seen is None:
        return {"last_seen": "\u2014", "duration": "\u2014",
                "episode": EpisodeStatus.UNKNOWN.label}
    return {
        "last_seen": format_local(episode.last_seen, "%d %b %H:%M:%S"),
        "duration": episode.duration_text,
        "episode": episode.status.label,
    }


class AlertsScreen(Screen):
    """Review and classify real Snort alerts."""

    title = "IDS Alerts"
    subtitle = "Snort intrusion detection alerts received over the configured transport"
    required_permission = "alert.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._alerts: dict[int, SnortAlert] = {}
        self._anomalies: dict[int, TrafficAnomaly] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the alerts screen."""
        self._build_status_bar()
        self._build_summary()
        self._build_filters()

        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, pady=(10, 0))

        table_card = Card(body, "Alerts", fonts=self.fonts, padding=12)
        table_card.pack(fill="both", expand=True)

        toolbar = Toolbar(table_card)
        toolbar.pack(fill="x", pady=(0, 6))
        # Buttons that act on the selected row. Held so they can be disabled
        # when there is nothing selected: a control that looks live and does
        # nothing is indistinguishable from a broken one.
        self._row_actions: dict[str, Any] = {}
        # Actions only a Snort alert can accept. Empty now that Acknowledge
        # and Escalate are gone; kept because the distinction is real - the
        # two detection sources carry different workflow columns - and
        # _paint_actions still asks it for every button.
        self._snort_only: set[str] = set()
        self._action_busy = False

        def act(label: str, command: Any) -> None:
            self._row_actions[label] = toolbar.add_button(label, command)

        act("Details", self._show_detail)
        act("Mark reviewed", lambda: self._set_status(AlertStatus.REVIEWED))
        toolbar.add_separator()
        act("True positive", lambda: self._classify(EvaluationLabel.TRUE_POSITIVE))
        act("False positive", lambda: self._classify(EvaluationLabel.FALSE_POSITIVE))
        # Acknowledge, Escalate and Benign/expected were removed as unused
        # actions. Only the *actions* went: AlertStatus.ACKNOWLEDGED and
        # ESCALATED and EvaluationLabel.BENIGN_EXPECTED remain, because
        # stored records still carry them - two alerts are ESCALATED and two
        # detections are classified BENIGN_EXPECTED on this installation -
        # and the Status and Evaluation columns must keep reporting them
        # truthfully. Nothing can be put *into* those states from here any
        # more; nothing already in them was touched.
        toolbar.add_separator()
        # Export is not a row action: it exports the filtered set, so it
        # stays available whether or not a row is selected.
        toolbar.add_button("Export", self._export)
        self._count_label = toolbar.add_label("", side="right")

        self._table = DataTable(
            table_card, ALERT_COLUMNS, height=16,
            on_select=self._preview, on_activate=lambda _row: self._show_detail(),
            empty_text="No alerts have been received on the configured transport",
            actions=[
                RowAction("View full alert", lambda _row: self._show_detail()),
                RowAction(
                    "Mark reviewed",
                    lambda _row: self._set_status(AlertStatus.REVIEWED),
                ),
                RowAction(
                    "Classify true positive",
                    lambda _row: self._classify(EvaluationLabel.TRUE_POSITIVE),
                ),
                RowAction(
                    "Classify false positive",
                    lambda _row: self._classify(EvaluationLabel.FALSE_POSITIVE),
                ),
            ],
        )
        self._table.pack(fill="both", expand=True)
        # Nothing is selected yet, so every row action starts disabled.
        self._paint_actions()

        preview = Card(self, "Alert evidence", fonts=self.fonts, padding=12)
        preview.pack(fill="x", pady=(10, 0))
        self._preview_text = tk.Text(preview, height=8, wrap="word")
        configure_text_widget(self._preview_text, self.fonts, mono=True)
        self._preview_text.insert("1.0", "Select an alert to see its evidence.")
        self._preview_text.configure(state="disabled")
        self._preview_text.pack(fill="x")

    def _build_status_bar(self) -> None:
        """Show the true Snort ingest state (§21)."""
        card = Card(self, "Snort status", fonts=self.fonts, padding=12)
        card.pack(fill="x")
        self._snort_label = ttk.Label(
            card, text="Checking...", style="CardMuted.TLabel",
            wraplength=1000, justify="left",
        )
        self._snort_label.pack(anchor="w")
        self._reliability_label = ttk.Label(card, text="", style="CardDim.TLabel")
        self._reliability_label.pack(anchor="w", pady=(4, 0))

    def _build_summary(self) -> None:
        """Severity counts, so the queue is graded before it is read.

        Each severity cell carries the manuscript's §3.9.8 rate band - on the
        card as text, and in full on hover. The bands are read from
        :data:`~aethra_sec.analytics.anomaly_rules.FLOOD_BANDS`, the one place
        they are defined, so the figure and its stated threshold cannot
        disagree. The counts themselves are untouched by this: they still
        arrive from ``detection_totals`` and are mapped by
        :func:`_summary_cells`, which this feature does not go near.

        UNREVIEWED deliberately has no band. It is a review state, and the
        manuscript's thresholds are about traffic rate.
        """
        high = flood_band(Severity.HIGH)
        medium = flood_band(Severity.MEDIUM)
        low = flood_band(Severity.LOW)
        self._summary = SummaryStrip(
            self,
            (
                SummaryCell("high", "High", PALETTE.high,
                            caption=high.range_text if high else "",
                            tooltip=high.explain() if high else ""),
                SummaryCell("medium", "Medium", PALETTE.medium,
                            caption=medium.range_text if medium else "",
                            tooltip=medium.explain() if medium else ""),
                SummaryCell("low", "Low", PALETTE.low,
                            caption=low.range_text if low else "",
                            tooltip=low.explain() if low else ""),
                SummaryCell(
                    "unreviewed", "Unreviewed", PALETTE.accent,
                    caption=f"{UNREVIEWED_MARK} in the table",
                    tooltip=(
                        "Detections nobody has triaged yet: Snort alerts "
                        "still NEW, and AETHRA-SEC detections still "
                        f"unclassified.\n\nEach one carries {UNREVIEWED_MARK} "
                        "in the Review column of the table below. This figure "
                        "and those marks are the same stored review state, "
                        "counted in the database over the filters now "
                        "applied.\n\nReview is not acknowledgement and not an "
                        "evaluation: an acknowledged alert can still be "
                        "unreviewed."
                    ),
                ),
            ),
            fonts=self.fonts,
        )
        self._summary.pack(fill="x", pady=(10, 0))

    def _build_filters(self) -> None:
        """Search and filter controls (§41, §42)."""
        card = Card(self, "Search and filter", fonts=self.fonts, padding=12)
        card.pack(fill="x", pady=(10, 0))
        row = FilterBar(card)
        row.pack(fill="x")

        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._search_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self._search_var, width=28)
        entry.pack(side="left", padx=(8, 14))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._severity_var = tk.StringVar(value="All")
        self._status_var = tk.StringVar(value="All")
        self._window_var = tk.StringVar(value="Last 24 hours")
        self._view_var = tk.StringVar(value=VIEW_EACH_DETECTION)
        self._source_var = tk.StringVar(value=SOURCE_AETHRA)
        #: Every detection of each attack shown, keyed by its primary row.
        self._attack_members: dict[tuple[str, Any], list[dict[str, Any]]] = {}
        #: Bounds for the Custom range, held as real datetimes.
        self._custom_range: tuple[datetime, datetime] | None = None
        for label, variable, values, width in (
            # DETECTION_SEVERITIES, not every Severity the enum can express:
            # CRITICAL is not part of this module's model, so offering it would
            # be offering a filter that can never match.
            ("Severity", self._severity_var,
             ["All", *[str(s) for s in DETECTION_SEVERITIES]], 12),
            ("Status", self._status_var,
             ["All", *[str(s) for s in AlertStatus]], 14),
            # NAMED_RANGES, the shared catalogue in models.periods. "Today"
            # is the Dashboard's own local-midnight boundary, so a count
            # filtered to Today here matches the Dashboard's daily figure.
            ("Period", self._window_var, list(NAMED_RANGES), 16),
            # One attack can raise several detections - AETHRA-SEC's flood
            # rule, Snort's flood rule, Snort's per-packet rule. "One row per
            # attack" shows each correlated attack once; the detections stay
            # recorded and are listed in its detail view.
            ("View", self._view_var,
             [VIEW_EACH_DETECTION, VIEW_ONE_PER_ATTACK], 18),
            # The primary alerts are AETHRA-SEC's detections. Snort's alerts
            # are evidence: a port scan alone leaves thousands of "TCP SYN
            # (any port)" rows (3,853 stored here), which listed beside the
            # detections read as thousands of attacks.
            ("Source", self._source_var, [SOURCE_AETHRA, SOURCE_SNORT], 26),
        ):
            ttk.Label(row, text=label, style="CardMuted.TLabel").pack(side="left")
            box = ttk.Combobox(
                row, textvariable=variable, values=values, state="readonly", width=width
            )
            box.pack(side="left", padx=(8, 14))
            if variable is self._window_var:
                # Choosing "Custom..." asks for the bounds straight away;
                # waiting until Apply would leave the control claiming a range
                # nobody entered.
                box.bind("<<ComboboxSelected>>", self._on_period_selected)
            elif variable is self._source_var:
                box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
            elif variable is self._view_var:
                # Changing the view regroups what is loaded; no query.
                box.bind("<<ComboboxSelected>>", lambda _e: self._regroup())

        ttk.Button(
            row, text="Apply", style="Accent.TButton", command=self.refresh
        ).pack(side="left", padx=(0, 6))
        ttk.Button(
            row, text="Reset", style="Ghost.TButton", command=self._reset_filters
        ).pack(side="left")
        # Named for what it does. The badge counts alerts in NEW, and leaving
        # that state records an analyst's judgement, so this is not offered as
        # "mark as read" and is not offered at all without alert.manage.
        if self.can(Permission.ALERT_MANAGE):
            self._mark_reviewed_button = ttk.Button(
                row, text="Mark all reviewed", style="Ghost.TButton",
                command=self._mark_all_reviewed,
            )
            self._mark_reviewed_button.pack(side="right")

    def _mark_all_reviewed(self) -> None:
        """Mark every untriaged detection reviewed, from either engine.

        Confirmed first, because it writes a decision onto every one of them.
        Alerts already acknowledged, escalated or suppressed are untouched.
        """
        service = self.context.snort
        session = self.session
        if service is None or session is None:
            return

        pending = self._pending_review_count()
        if not pending:
            self.status("No detections are waiting for review.")
            return
        if not confirm(
            self,
            "Mark all detections as reviewed?",
            f"{pending} detection(s) have not been triaged yet.",
            detail=(
                "Snort alerts still in NEW are recorded as REVIEWED by you, "
                "which is an analyst judgement and appears in the audit "
                "trail; AETHRA-SEC's own detections are stamped as read by "
                "you. Alerts you have already acknowledged, escalated or "
                "suppressed are not changed, no evaluation label is assigned, "
                "and nothing is deleted."
            ),
            confirm_label="Mark reviewed",
        ):
            return

        def work() -> int:
            return service.mark_all_reviewed(session)

        def done(moved: int) -> None:
            self.status(f"{moved} detection(s) marked as reviewed.")
            self.refresh()
            refresh_badges = getattr(self.app, "_refresh_nav_badges", None)
            if callable(refresh_badges):
                refresh_badges()

        self.run_async(work, on_success=done, name="alerts-mark-reviewed")

    def _pending_review_count(self) -> int:
        """Detections nobody has triaged yet, across both engines.

        Counts what the UNREVIEWED cell counts, not what the sidebar badge
        counts. Asking only for Snort's NEW queue turned this into the gate
        that stopped the action: with Snort quiet and the whole backlog raised
        by AETHRA-SEC's own rules, the button answered "nothing is waiting"
        and the counter it exists to clear never moved.
        """
        service = self.context.snort
        session = self.session
        if service is None or session is None:
            return 0
        total = 0
        for count in (
            service.unresolved_alert_count,
            service.unreviewed_anomaly_count,
        ):
            try:
                total += int(count(session))
            except Exception:  # noqa: BLE001 - a count must not block the action
                continue
        return total

    def _on_period_selected(self, _event: object = None) -> None:
        """Ask for the bounds when Custom is chosen, then reload."""
        if self._window_var.get() == CUSTOM_RANGE:
            if not self._prompt_custom_range():
                # Cancelled: fall back rather than leave "Custom..." showing a
                # range the operator never entered.
                self._window_var.set("Last 24 hours")
                return
        self.refresh()

    def _prompt_custom_range(self) -> bool:
        """Collect an explicit from/to. Returns True when both parsed."""
        today = local_today()
        values = FormDialog(
            self, "Detections in a custom range",
            [
                FormField(
                    "start", "From", value=f"{today} 00:00", required=True,
                    help_text="YYYY-MM-DD HH:MM, in your local timezone.",
                ),
                FormField(
                    "end", "To (exclusive)", value=f"{today} 23:59", required=True,
                    help_text=(
                        "Exclusive: a detection stamped exactly at this time "
                        "belongs to the next range."
                    ),
                ),
            ],
            fonts=self.fonts, submit_label="Show range",
            validator=lambda v: (
                ""
                if parse_moment(v.get("start")) and parse_moment(v.get("end"))
                else "Enter both bounds as YYYY-MM-DD HH:MM."
            ),
        ).show()
        if not values:
            return False
        begins = parse_moment(values.get("start"))
        ends = parse_moment(values.get("end"))
        if begins is None or ends is None:
            return False
        self._custom_range = (begins, ends) if begins <= ends else (ends, begins)
        return True

    def _selected_period(self) -> DashboardPeriod | None:
        """The period the Period control names.

        ``None`` means no time bound at all, which is what "All data" asks
        for - the query then carries neither ``start`` nor ``end``.
        """
        choice = self._window_var.get()
        if choice == CUSTOM_RANGE:
            if self._custom_range is None:
                return None
            return DashboardPeriod.custom(*self._custom_range)
        period = period_for_range(choice)
        if period is None or period.start is None:
            return None
        return period

    def _reset_filters(self) -> None:
        """Clear every filter."""
        self._search_var.set("")
        self._severity_var.set("All")
        self._status_var.set("All")
        self._window_var.set("Last 24 hours")
        self._view_var.set(VIEW_EACH_DETECTION)
        self._source_var.set(SOURCE_AETHRA)
        self._custom_range = None
        self.refresh()

    def set_search(self, text: str) -> None:
        """Open the screen filtered to one address or signature (drill-down)."""
        self._search_var.set(str(text or ""))
        self._window_var.set("All data")
        self.refresh()

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload alerts using the current filters.

        Single-flight. Every new detection from either engine calls this, and
        each call used to start its own worker running both searches, the
        totals and a rate query per detection, then rebuild a table of up to
        1,000 rows on the Tk thread - so a burst of alerts queued that much
        work once per alert. A refresh asked for while one is running now
        sets a flag, and exactly one more load runs when it finishes, which
        still shows the newest data.
        """
        if getattr(self, "_load_running", False):
            self._load_again = True
            return
        snort = self.context.snort
        dashboard = self.context.dashboard
        session = self.session
        if snort is None or session is None:
            return
        self._update_snort_status()

        filters: dict[str, Any] = {"limit": 1000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._severity_var.get() != "All":
            filters["severity"] = self._severity_var.get()
        if self._status_var.get() != "All":
            filters["status"] = self._status_var.get()
        # Resolved by the shared range table, so every option carries both
        # bounds and is the identical half-open window the Dashboard reports
        # on - rather than a start that then runs on to the present.
        period = self._selected_period()
        if period is not None:
            filters["start"] = period.start
            filters["end"] = period.end

        self.status("Loading detections...")
        # Read the Tk variable here, on the Tk thread. A worker must not touch
        # Tk state, and asking a status filter means the operator is looking at
        # Snort's own workflow queue, which anomalies are not part of.
        snort_queue_only = self._status_var.get() != "All"
        snort_view = self._source_var.get() == SOURCE_SNORT

        def work() -> tuple[
            list[SnortAlert], list[TrafficAnomaly], dict[str, int],
            dict[tuple[str, int], float],
        ]:
            """Both detection sources, plus the totals for the same filters.

            The rows are capped at ``ROW_LIMIT`` so the table stays responsive;
            the summary is counted in the database over the identical
            predicate, with no cap. Tallying the summary from the returned rows
            instead made the row limit part of the count, which is why this
            screen and the Dashboard disagreed by exactly the detections that
            did not fit on the page.
            """
            # One source per view. Snort alerts are queried only for the
            # evidence view, and the totals count only the source listed, so
            # the summary never counts Snort alerts as AETHRA-SEC detections.
            alerts = snort.search(session, **filters) if snort_view else []
            # The anomaly store shares severity, text and time filters but has
            # no status or priority, so only the filters that mean the same
            # thing on both sides are passed through.
            anomaly_filters = {
                key: value
                for key, value in filters.items()
                if key in ("text", "severity", "start", "limit")
            }
            if snort_view:
                anomalies: list[TrafficAnomaly] = []
            else:
                # The Snort workflow status filter has no meaning for
                # AETHRA-SEC detections and is ignored in this view.
                anomalies = snort.search_anomalies(session, **anomaly_filters)

            counted = {k: v for k, v in filters.items() if k != "limit"}
            counted_anomaly = {
                k: v for k, v in anomaly_filters.items() if k != "limit"
            }
            if snort_view:
                totals = snort.snort_evidence_totals(session, counted)
            else:
                totals = snort.aethra_detection_totals(session, counted_anomaly)
            # A real pps for every detection that does not store one, measured
            # here on the worker so the Tk thread never waits on it.
            rates = _measure_rates(dashboard, alerts, anomalies)
            return alerts, anomalies, totals, rates

        self._load_running = True
        self._load_again = False

        def finished() -> None:
            self._load_running = False
            if getattr(self, "_load_again", False) and self.is_alive:
                self._load_again = False
                self.refresh()

        def applied(result: Any) -> None:
            try:
                self._apply(result)
            finally:
                finished()

        def failed(message: str) -> None:
            try:
                self.show_error_message(message)
            finally:
                finished()

        self.run_async(work, applied, failed, name="alerts-load")

    def _apply(
        self,
        loaded: tuple[
            list[SnortAlert], list[TrafficAnomaly], dict[str, int],
            dict[tuple[str, int], float],
        ],
    ) -> None:
        """Render both detection sources in one table, newest first."""
        alerts, anomalies, totals, rates = loaded
        self._last_loaded = loaded
        self._alerts = {a.id: a for a in alerts if a.id is not None}
        self._anomalies = {a.id: a for a in anomalies if a.id is not None}

        # The summary describes every matching detection, not the page of them
        # that was loaded, and comes from the same query the Dashboard uses.
        self._summary.update_counts(_summary_cells(totals))

        rows = self._alert_rows(alerts, rates) + self._anomaly_rows(
            anomalies, rates
        )
        # One ordering across both sources, so the newest detection is at the
        # top whichever engine raised it.
        rows.sort(key=lambda row: row["_sort"], reverse=True)
        detections_loaded = len(rows)
        attacks, members = one_row_per_attack(rows)
        self._attack_members = members
        per_attack = self._view_var.get() == VIEW_ONE_PER_ATTACK
        self._table.set_rows(attacks if per_attack else rows)
        # set_rows clears the selection, so the buttons follow it back down.
        self._paint_actions()

        shown = detections_loaded
        matching = int(totals.get("total", shown))
        attack_note = (
            f" · {len(attacks):,} attack(s) among the {detections_loaded:,} "
            "loaded (correlated detections counted once)"
        )
        # When the cap bites, say so. A table quietly showing 1,000 of 1,412
        # while the summary says 1,412 would look like a fresh inconsistency
        # rather than the row limit it is.
        truncated = matching > shown
        if self._source_var.get() == SOURCE_SNORT:
            count_text = (
                f"{matching:,} Snort alert record(s) - supporting evidence, not "
                "AETHRA-SEC detections"
                + (f" · showing newest {shown:,}" if truncated else "")
            )
        else:
            count_text = (
                f"{matching:,} AETHRA-SEC detection(s)"
                + (f" · showing newest {shown:,}" if truncated else "")
                + attack_note
            )
        self._count_label.configure(text=count_text)
        if not matching:
            self.status("No detections match the current filters.")
        elif truncated:
            self.status(
                f"{matching:,} detection(s) match; showing the newest "
                f"{shown:,}. Narrow the filters to see the rest."
            )
        else:
            self.status(
                f"{matching:,} detection(s): {len(alerts):,} from Snort, "
                f"{len(anomalies):,} from AETHRA-SEC's own rules."
            )

    def _regroup(self) -> None:
        """Re-render what is loaded in the chosen view, without a new query."""
        loaded = getattr(self, "_last_loaded", None)
        if loaded is None:
            self.refresh()
            return
        self._apply(loaded)

    def _anomaly_rows(
        self,
        anomalies: list[TrafficAnomaly],
        rates: dict[tuple[str, int], float] | None = None,
    ) -> list[dict[str, Any]]:
        """Rows for detections raised by AETHRA-SEC's own rules."""
        rates = rates or {}
        rows: list[dict[str, Any]] = []
        for anomaly in anomalies:
            when = anomaly.detected_at or anomaly.last_seen or anomaly.created_at
            rows.append(
                {
                    "_id": anomaly.id,
                    "_origin": ORIGIN_AETHRA,
                    "_attack": anomaly.incident_id,
                    "_sort": when,
                    # From the detection's own stored review state, through
                    # the one predicate the UNREVIEWED counter's SQL mirrors.
                    # Never from severity, age, row position or index.
                    "review": _review_cell(anomaly),
                    "time": format_local(when, "%d %b %H:%M:%S") if when else "-",
                    "origin": "AETHRA-SEC",
                    "severity": str(anomaly.severity),
                    "now": _current_band(anomaly),
                    "rate": _measured_rate(
                        anomaly, rates.get((ORIGIN_AETHRA, anomaly.id))
                    ),
                    "priority": "-",
                    "signature": anomaly.rule_id,
                    "message": anomaly.title or anomaly.observation or "-",
                    "protocol": anomaly.protocol or "-",
                    "source": anomaly.src_ip or "-",
                    "destination": (
                        f"{anomaly.dst_ip}:{anomaly.dst_port}"
                        if anomaly.dst_port
                        else anomaly.dst_ip or "-"
                    ),
                    # Observations in the record - never the legacy count
                    # that started at the trigger rate (see measurement_count).
                    "count": (
                        measurement_count(anomaly)[0]
                        if measurement_count(anomaly)[0] is not None else "-"
                    ),
                    **_episode_cells(anomaly, _episode_timeout(self)),
                    # Anomalies carry no Snort workflow status. Saying so is
                    # more honest than borrowing a status they do not have.
                    "status": "-",
                    "evaluation": anomaly.evaluation.label,
                }
            )
        return rows

    def _alert_rows(
        self,
        alerts: list[SnortAlert],
        rates: dict[tuple[str, int], float] | None = None,
    ) -> list[dict[str, Any]]:
        """Rows for alerts ingested from Snort."""
        rates = rates or {}
        timeout = _episode_timeout(self)
        return [
                {
                    "_id": alert.id,
                    "_origin": ORIGIN_SNORT,
                    "_attack": alert.incident_id,
                    "_sort": alert.effective_time,
                    # See _anomaly_rows: the stored state, not an inference.
                    "review": _review_cell(alert),
                    "origin": "Snort",
                    "time": format_local(alert.effective_time, "%d %b %H:%M:%S"),
                    "severity": str(alert.severity),
                    # The Now band is left to the flood rules. The Rate column
                    # shows the pps this alert was graded on (peak_pps); older
                    # alerts graded by Snort priority show the source's rate
                    # measured from captured traffic instead.
                    "now": "-",
                    "rate": _format_pps(
                        alert.peak_pps
                        if getattr(alert, "peak_pps", None) is not None
                        else rates.get((ORIGIN_SNORT, alert.id))
                    ),
                    "priority": alert.priority if alert.priority is not None else "-",
                    "signature": alert.signature_text,
                    "message": alert.message or "-",
                    "protocol": alert.protocol or "-",
                    "source": (
                        f"{alert.src_ip}:{alert.src_port}"
                        if alert.src_port
                        else alert.src_ip or "-"
                    ),
                    "destination": (
                        f"{alert.dst_ip}:{alert.dst_port}"
                        if alert.dst_port
                        else alert.dst_ip or "-"
                    ),
                    "count": alert.duplicate_count,
                    **_episode_cells(alert, timeout),
                    "status": str(alert.status),
                    "evaluation": alert.evaluation.label,
                }
                for alert in alerts
        ]

    def _update_snort_status(self) -> None:
        """Show the real transport state and reliability counters (§84)."""
        snort = self.context.snort
        if snort is None:
            return
        status = snort.status()
        self._snort_label.configure(
            text=(
                f"{status.status_text} · transport: {status.transport} · "
                f"{status.endpoint or 'not configured'}"
                f"{_source_silence_note(snort)}\n{status.detail}"
            ),
            foreground=state_colour(
                "RUNNING" if status.is_connected else
                "DISABLED" if status.transport == "disabled" else "OFFLINE"
            ),
        )
        counters = snort.reliability()
        self._reliability_label.configure(
            text=(
                f"received {format_count(counters['received'])} · "
                f"stored {format_count(counters['stored'])} · "
                f"duplicates folded {format_count(counters['duplicates'])} · "
                f"parse failures {format_count(counters['parse_failures'])} · "
                f"correlated {format_count(counters['correlated'])} · "
                f"unreviewed {format_count(counters['unresolved'])}"
                + (
                    f" · last alert {format_local(status.last_alert_at)}"
                    if status.last_alert_at
                    else ""
                )
            )
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _selected_alert(self) -> SnortAlert | None:
        """The selected row, when it is a Snort alert.

        Returns None for a row raised by AETHRA-SEC's own rules, so an action
        that only applies to Snort's workflow cannot silently act on the wrong
        kind of record.
        """
        row = self._table.selected_row()
        if row is None or row.get("_origin") != ORIGIN_SNORT:
            return None
        return self._alerts.get(int(row.get("_id") or 0))

    def _selected_anomaly(self) -> TrafficAnomaly | None:
        """The selected row, when it is one of AETHRA-SEC's own detections."""
        row = self._table.selected_row()
        if row is None or row.get("_origin") != ORIGIN_AETHRA:
            return None
        return self._anomalies.get(int(row.get("_id") or 0))

    def _paint_actions(self) -> None:
        """Enable only the actions the selected row can actually accept.

        Three states, and the middle one is the reason this exists: nothing
        selected disables every row action; an AETHRA-SEC detection disables
        the two Snort-only workflow states, which it has no column for; a
        Snort alert enables everything.
        """
        alert = self._selected_alert()
        anomaly = self._selected_anomaly()
        for label, button in self._row_actions.items():
            if self._action_busy:
                usable = False
            elif alert is not None:
                usable = True
            elif anomaly is not None:
                usable = label not in self._snort_only
            else:
                usable = False
            try:
                button.state(["!disabled"] if usable else ["disabled"])
            except tk.TclError:  # pragma: no cover - torn down
                return

    def _preview(self, _row: dict[str, Any]) -> None:
        """Show the selected alert's evidence in the preview pane."""
        self._paint_actions()
        alert = self._selected_alert()
        self._preview_text.configure(state="normal")
        self._preview_text.delete("1.0", "end")
        if alert is None:
            self._preview_text.insert("1.0", "Select an alert to see its evidence.")
        else:
            latency = alert.detection_latency_seconds
            self._preview_text.insert(
                "1.0",
                "\n".join(
                    [
                        f"Signature      : {alert.signature_text}  {alert.message}",
                        f"Classification : {alert.classification or 'not supplied by the sensor'}",
                        f"Severity       : {alert.severity} (Snort priority "
                        f"{alert.priority if alert.priority is not None else 'not supplied'})",
                        f"Sensor time    : {format_local_ms(alert.alert_time) if alert.alert_time else 'not supplied'}"
                        f"   ({alert.time_source})",
                        f"Received       : {format_local_ms(alert.received_at)}",
                        f"Ingest latency : {f'{latency:.3f} s' if latency is not None else 'not measurable - sensor supplied no timestamp'}",
                        f"Endpoints      : {alert.src_ip or '-'}:{alert.src_port or '-'}"
                        f" -> {alert.dst_ip or '-'}:{alert.dst_port or '-'} ({alert.protocol or '-'})",
                        f"Transport      : {alert.transport or '-'}    Sensor: {alert.sensor or '-'}",
                        f"Occurrences    : {alert.duplicate_count}",
                        "",
                        "RAW ALERT EVIDENCE:",
                        alert.raw_alert or "(the transport supplied no raw text)",
                    ]
                ),
            )
        self._preview_text.configure(state="disabled")

    def _show_detail(self) -> None:
        """Open the full detail for the selected row, whichever engine made it.

        One entry point for all three ways in - the Details button, a
        double-click and the right-click menu - so there is a single full
        alert view rather than three that can drift apart.

        The mitigation lookup runs on a worker: it reads the knowledge base,
        and a database round trip on the Tk thread freezes the window. The
        dialog is built once the guidance is in hand, so nothing is queried
        again while it is open.
        """
        anomaly = self._selected_anomaly()
        if anomaly is not None:
            self._open_detail(anomaly, snort=False)
            return
        alert = self._selected_alert()
        if alert is None:
            self.status("Select a detection first.")
            return
        self._open_detail(alert, snort=True)

    def _open_detail(self, detection: Any, *, snort: bool) -> None:
        """Resolve the mitigation guidance, then render the full view.

        Opening a detection is a read. It records no review, changes no
        status and writes no evaluation: "I looked at this" and "I have
        triaged this" are different claims, and only the buttons make the
        second one.
        """
        if not snort:
            self._open_anomaly_detail(detection)
            return
        render = self._render_alert_detail
        mitigation = self.context.mitigation
        if mitigation is None:
            # No mitigation service wired: say so rather than leaving the
            # section out, so its absence cannot read as "no guidance exists".
            render(detection, None)
            return

        resolve = (
            mitigation.match_for_alert if snort else mitigation.match_for_anomaly
        )
        self.status("Loading detection detail...")
        self.run_async(
            lambda: resolve(detection),
            lambda match: render(detection, match),
            on_error=lambda message: render(
                detection,
                MitigationMatch(lookup_failed=True, failure_detail=message),
            ),
            name="detection-detail",
        )

    def _open_anomaly_detail(self, anomaly: Any) -> None:
        """Resolve guidance and the linked Snort evidence on a worker, then render."""
        mitigation = self.context.mitigation
        snort = self.context.snort
        session = self.session

        def work() -> tuple[Any, Any]:
            match = None
            if mitigation is not None:
                try:
                    match = mitigation.match_for_anomaly(anomaly)
                except Exception as exc:  # noqa: BLE001 - shown in the dialog
                    match = MitigationMatch(lookup_failed=True, failure_detail=str(exc))
            evidence: Any = None
            if snort is not None and anomaly.incident_id:
                try:
                    evidence = snort.snort_evidence_for_attack(
                        session, int(anomaly.incident_id)
                    )
                except Exception as exc:  # noqa: BLE001 - shown in the dialog
                    evidence = exc
            return match, evidence

        self.status("Loading detection detail...")
        self.run_async(
            work,
            lambda result: self._render_anomaly_detail(
                anomaly, result[0], snort_evidence=result[1]
            ),
            name="detection-detail",
        )

    def _mitigation_actions(
        self, match: MitigationMatch | None
    ) -> tuple[list[tuple[str, Any]], dict[str, Any]]:
        """The "View in Mitigation" button, when there is a record to open.

        Offered only when the lookup actually resolved to a stored entry and
        the operator may read the knowledge base. It opens the existing
        record; nothing is created by viewing an alert.
        """
        holder: dict[str, Any] = {}
        if (
            match is None
            or not match.resolved
            or match.recommendation is None
            or not self.can(Permission.MITIGATION_VIEW)
        ):
            return [], holder
        code = match.recommendation.code

        def open_in_mitigation() -> None:
            dialog = holder.get("dialog")
            if dialog is not None:
                # The detail view is modal, so it is dismissed before the
                # navigation rather than left grabbing the pointer.
                dialog.cancel()
            self.app.navigate("mitigation", focus_code=code)

        return [("View in Mitigation", open_in_mitigation)], holder

    def _render_alert_detail(
        self, alert: SnortAlert, match: MitigationMatch | None
    ) -> None:
        """The full alert view: what the sensor reported, and what to do.

        Every field is the stored alert's own. Where the sensor supplied
        nothing the view says so - an absent classification or timestamp is
        itself information about the detection, and filling it in would make
        the record look more complete than it is.
        """
        latency = alert.detection_latency_seconds
        _alert_episode = alert.episode(
            inactivity_seconds=_episode_timeout(self)
        )
        sections: list[DetailSection] = [
            DetailSection(
                "ALERT INFORMATION",
                rows=[
                    ("Alert ID", _value(alert.id)),
                    ("Detected", _stamp(alert.effective_time)),
                    ("Detected by", _detected_by(alert)),
                    ("Severity", str(alert.severity)),
                    ("Snort priority", _value(alert.priority, "Not supplied")),
                    ("Signature", alert.signature_text),
                    ("Rule (GID:SID:Rev)", _rule_text(alert)),
                    ("Message", _value(alert.message, "Not supplied")),
                    ("Classification", _value(alert.classification, "Not supplied")),
                ],
            ),
            DetailSection(
                "OBSERVED EPISODE",
                rows=[
                    ("Occurrences", _value(alert.duplicate_count)),
                    ("First observed", _stamp(alert.first_observed)),
                    ("Last observed", _stamp(alert.last_observed)),
                    ("Observed duration", _alert_episode.duration_text),
                    ("Episode status", _alert_episode.status.label),
                    ("What that means", _alert_episode.status.explanation),
                    (
                        "Note",
                        "The duration is the span between the first and last "
                        "observation. It does not assert that traffic was "
                        "continuously present throughout, and a gap in "
                        "observations is not evidence the activity stopped. "
                        "This is not detection time (section 3.9.2), which "
                        "needs a separately recorded attack-initiation "
                        "timestamp.",
                    ),
                ],
            ),
            DetailSection(
                "NETWORK DETAILS",
                rows=[
                    ("Protocol", _value(alert.protocol)),
                    ("Source IP", _value(alert.src_ip)),
                    ("Source port", _value(alert.src_port)),
                    ("Destination IP", _value(alert.dst_ip)),
                    ("Destination port", _value(alert.dst_port)),
                    ("Interface", _value(alert.interface)),
                ],
            ),
            DetailSection(
                "EVIDENCE",
                rows=[
                    ("Evidence source", "Snort"),
                    ("Sensor", _value(alert.sensor)),
                    ("Transport", _value(alert.transport)),
                    ("Sensor timestamp", _stamp(alert.alert_time, precise=True)),
                    ("Timestamp source", _value(alert.time_source)),
                    ("Received", _stamp(alert.received_at, precise=True)),
                    (
                        "Ingest latency",
                        f"{latency:.3f} s" if latency is not None
                        else "Not measurable - the sensor supplied no timestamp",
                    ),
                    ("Occurrences folded into this row", str(alert.duplicate_count)),
                ],
            ),
            _mitigation_section(match, alert),
            DetailSection(
                "WORKFLOW STATUS",
                rows=[
                    # Three separate facts, kept apart. Review state is what
                    # the row mark and the UNREVIEWED counter report; the
                    # workflow status carries ACKNOWLEDGED and ESCALATED,
                    # which are not review; the evaluation is the analyst's
                    # verdict, which is neither. An alert can be acknowledged
                    # without having been marked reviewed.
                    ("Review status", _review_status_text(alert)),
                    ("Workflow status", str(alert.status)),
                    ("Analyst evaluation", alert.evaluation.label),
                    ("Evaluated at", _stamp(alert.evaluated_at)),
                    # No "reviewed by"/"reviewed at" rows: snort_alerts stores
                    # neither. evaluated_by/at above belong to the evaluation,
                    # not the review, and presenting them as review metadata
                    # would attribute a decision nobody recorded.
                ],
            ),
            DetailSection(
                "RAW ALERT",
                body=alert.raw_alert or "The transport supplied no raw text.",
                collapsed=True,
            ),
        ]
        related = _related_section(
            self._attack_members.get((ORIGIN_SNORT, alert.id)), ORIGIN_SNORT, alert.id
        )
        if related is not None:
            sections.insert(len(sections) - 1, related)
        actions, holder = self._mitigation_actions(match)
        dialog = DetailDialog(
            self, f"Alert {alert.id} - {alert.signature_text}",
            rows=[], sections=sections, actions=actions, fonts=self.fonts,
            width=820, height=640,
        )
        holder["dialog"] = dialog
        self.status(_detail_status(match))
        dialog.show()

    def _set_status(self, status: AlertStatus) -> None:
        """Change the selected detection's workflow state.

        Only Snort alerts carry the workflow. AETHRA-SEC's own detections
        carry a read receipt instead, so REVIEWED is routed onto that receipt
        rather than being refused with "select an alert first" - which, with a
        row plainly selected, read as the button doing nothing while the
        UNREVIEWED cell stayed where it was.
        """
        anomaly = self._selected_anomaly()
        if anomaly is not None:
            self._review_anomaly(anomaly, status)
            return
        alert = self._selected_alert()
        snort = self.context.snort
        session = self.session
        if alert is None or alert.id is None or snort is None or session is None:
            self.status("Select an alert first.")
            return
        self.run_async(
            lambda: snort.set_status(session, alert.id or 0, status),
            lambda _r: (self.status(f"Alert {alert.id} marked {status}."), self.refresh()),
            name="alert-status",
        )

    def _review_anomaly(self, anomaly: TrafficAnomaly, status: AlertStatus) -> None:
        """Write the read receipt for one of AETHRA-SEC's own detections.

        The Snort-only states say so plainly instead of failing silently: an
        anomaly cannot be acknowledged or escalated because it never held that
        status to begin with.
        """
        if status is not AlertStatus.REVIEWED:
            self.status(
                f"{status} is a Snort workflow state. An AETHRA-SEC detection "
                "can only be marked reviewed."
            )
            return
        snort = self.context.snort
        session = self.session
        if anomaly.id is None or snort is None or session is None:
            return
        anomaly_id = int(anomaly.id)
        if anomaly.reviewed_at is not None:
            self.status(f"Detection {anomaly_id} was already marked reviewed.")
            return

        def done(marked: bool) -> None:
            self.status(
                f"Detection {anomaly_id} marked as reviewed."
                if marked
                else f"Detection {anomaly_id} was already marked reviewed."
            )
            self.refresh()

        self.run_async(
            lambda: snort.mark_anomaly_reviewed(session, anomaly_id),
            done,
            name="anomaly-review",
        )

    def _classify(self, label: EvaluationLabel) -> None:
        """Record the analyst's true/false-positive judgement (§82).

        Applies to either detection source. It used to refuse for AETHRA-SEC's
        own detections, which on an installation where Snort is quiet meant a
        verdict could be recorded for almost none of them - and those verdicts
        are what the detection-accuracy statistics are computed from.
        """
        anomaly = self._selected_anomaly()
        if anomaly is not None:
            self._classify_anomaly(anomaly, label)
            return
        alert = self._selected_alert()
        snort = self.context.snort
        session = self.session
        if alert is None or alert.id is None or snort is None or session is None:
            self.status("Select an alert first.")
            return
        self.run_async(
            lambda: snort.classify(session, alert.id or 0, label),
            lambda _r: (
                self.status(f"Alert {alert.id} classified as {label.label}."),
                self.refresh(),
            ),
            name="alert-classify",
        )

    def _render_anomaly_detail(
        self, anomaly: TrafficAnomaly, match: MitigationMatch | None,
        snort_evidence: Any = None,
    ) -> None:
        """Everything stored about one AETHRA-SEC detection, plus its guidance.

        Only fields the record actually has. Where a value was never supplied
        it says so rather than being filled in - an absent measurement is
        itself information about the detection.

        The mitigation block is resolved from the category the rule itself
        recorded, so no keyword guessing stands between the detection and its
        guidance. These detections had no mitigation section at all, which on
        an installation where most detections come from AETHRA-SEC's own rules
        meant the guidance was effectively unreachable from the queue.
        """
        when = anomaly.detected_at or anomaly.last_seen or anomaly.created_at
        _anomaly_episode = anomaly.episode(
            inactivity_seconds=_episode_timeout(self)
        )
        evidence = anomaly.evidence or {}
        # Built from this record alone, by a pure function, so what the dialog
        # shows can be tested without a window and cannot pick up values from
        # whichever detection was opened before.
        sections: list[DetailSection] = _anomaly_detail_sections(
            anomaly, when, _anomaly_episode
        )
        sections += [
            _mitigation_section(match, anomaly),
            DetailSection(
                "WORKFLOW STATUS",
                rows=[
                    ("Review status", _review_status_text(anomaly)),
                    (
                        "Reviewed at",
                        _stamp(anomaly.reviewed_at) if anomaly.reviewed_at
                        else "Not yet reviewed",
                    ),
                    # traffic_anomalies does store who marked it, unlike
                    # snort_alerts, so it is shown - as the stored id when no
                    # name is on the record, never as an invented username.
                    (
                        "Reviewed by",
                        f"user {anomaly.reviewed_by}" if anomaly.reviewed_by
                        else "Not recorded",
                    ),
                    ("Analyst evaluation", _value(anomaly.evaluation)),
                ],
            ),
            DetailSection(
                "RAW EVIDENCE",
                rows=[(k, str(v)) for k, v in sorted(evidence.items())],
                body="" if evidence else "The rule recorded no evidence fields.",
                collapsed=True,
            ),
        ]
        related = _related_section(
            self._attack_members.get((ORIGIN_AETHRA, anomaly.id)),
            ORIGIN_AETHRA, anomaly.id,
        )
        if related is not None:
            sections.insert(4, related)
        sections.insert(4, snort_evidence_section(anomaly, snort_evidence))
        actions, holder = self._mitigation_actions(match)
        dialog = DetailDialog(
            self, f"Detection {anomaly.id} - {anomaly.title}",
            rows=[], sections=sections, actions=actions, fonts=self.fonts,
            width=820, height=640,
        )
        holder["dialog"] = dialog
        self.status(_detail_status(match))
        dialog.show()

    # ------------------------------------------------------------------
    # Busy state
    # ------------------------------------------------------------------
    def _begin_action(self) -> None:
        """Block the action buttons while one is in flight.

        Without this a second click starts a second write before the first has
        returned, which for an evaluation means two audit records for one
        decision.
        """
        self._action_busy = True
        self._paint_actions()
        self.status("Working...")

    def _after_action(self, message: str) -> None:
        """Report a *completed* action and reload from the database.

        The message is shown here, on the success path, so it can never be
        printed for an operation that failed. The counters and the table are
        re-read rather than adjusted, so the database stays the source of
        truth.
        """
        self._action_busy = False
        self.status(message)
        self.refresh()
        self.app.refresh_notifications()

    def _action_failed(self, message: str) -> None:
        """Report a failure in the operator's terms."""
        self._action_busy = False
        self._paint_actions()
        self.show_error_message(message, title="Action failed")

    def _classify_anomaly(
        self, anomaly: TrafficAnomaly, label: EvaluationLabel
    ) -> None:
        """Record a verdict on one of AETHRA-SEC's own detections.

        The verdict is stored beside the detection, never over it: the rule
        that fired, the value it measured and the threshold it crossed are
        unchanged, so a detection classified FALSE_POSITIVE stays traceable to
        the evidence that produced it.
        """
        snort = self.context.snort
        session = self.session
        if anomaly.id is None or snort is None or session is None:
            self.status("Select a detection first.")
            return
        anomaly_id = anomaly.id
        self._begin_action()
        self.run_async(
            lambda: snort.classify_anomaly(session, anomaly_id, label),
            lambda _r: self._after_action(
                f"Evaluation recorded: {str(label).replace('_', ' ').title()}."
            ),
            on_error=lambda message: self._action_failed(message),
            name="anomaly-classify",
        )

    def _export(self) -> None:
        """Export the visible alerts to CSV."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._table.export_rows(visible_only=True)
        columns = self._table.export_columns()
        self.run_async(
            lambda: str(
                reports.export_records(
                    session, columns, rows, filename=f"alerts_{len(rows)}",
                    description="IDS alerts",
                )
            ),
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} alert(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="alert-export",
        )

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """Refresh when a new detection arrives, from either engine.

        This screen listened for Snort alerts only. A detection raised by
        AETHRA-SEC's own rules was stored and counted but never brought the
        screen up to date, so an operator watching during an attack saw
        nothing move until they reloaded by hand - which reads as "the system
        did not detect it".
        """
        if event.type in (
            EventType.SNORT_ALERT_RECEIVED,
            EventType.TRAFFIC_ANOMALY_DETECTED,
        ):
            self.refresh()
        elif event.type == EventType.SNORT_STATUS_CHANGED:
            self._update_snort_status()
