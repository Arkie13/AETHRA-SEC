"""The reported ICMP/UDP severity bug and the silent-notification bug.

Both were traced to real causes rather than guessed at, and both are pinned
here so the next optimisation cannot quietly undo them:

* an episode's ``severity`` is the worst rate it validly measured, and is
  never lowered by a later, slower sample - a UDP flood that reached 1,733
  pps used to read LOW once it tailed off below 500, and that one column
  drives the badge, the counters, the filter, exports, the dashboard and
  notification eligibility;
* the severity-to-level mapping is faithful, so ``sound_min_level`` means
  what it says - everything below HIGH used to become INFO, which made a
  MEDIUM detection pop up in silence.

The packet rates used below are test fixtures. They are not observations of
any real network.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.analytics.anomaly_rules import flood_severity
from aethra_sec.models.enums import NotificationLevel, Severity


# ---------------------------------------------------------------------------
# A - the severity boundaries, exactly as specified
# ---------------------------------------------------------------------------
class TestTheSeverityBoundaries:
    @pytest.mark.parametrize("rate,expected", [
        (499.0, Severity.LOW),
        (500.0, Severity.MEDIUM),
        (750.0, Severity.MEDIUM),
        (999.0, Severity.MEDIUM),
        (1000.0, Severity.HIGH),
        (1200.0, Severity.HIGH),
        (2000.0, Severity.HIGH),
    ])
    def test_the_specified_table(self, rate: float, expected: Severity) -> None:
        band, _summary = flood_severity(rate)
        assert band is expected, f"{rate} pps classified {band}, expected {expected}"

    @pytest.mark.parametrize("rate", [499.99, 499.9999])
    def test_just_below_the_medium_floor_is_low(self, rate: float) -> None:
        assert flood_severity(rate)[0] is Severity.LOW

    @pytest.mark.parametrize("rate", [999.99, 999.9999])
    def test_just_below_the_high_floor_is_medium(self, rate: float) -> None:
        assert flood_severity(rate)[0] is Severity.MEDIUM

    def test_the_floors_are_inclusive(self) -> None:
        """The boundary the user specified twice: 1,000 is HIGH, not MEDIUM."""
        assert flood_severity(1000.0)[0] is Severity.HIGH
        assert flood_severity(500.0)[0] is Severity.MEDIUM

    def test_a_zero_or_negative_rate_classifies_nothing_high(self) -> None:
        for rate in (0.0, -1.0):
            assert flood_severity(rate)[0] is Severity.LOW


# ---------------------------------------------------------------------------
# B - what the configured threshold actually is
# ---------------------------------------------------------------------------
class TestTheConfiguredThresholdsAreDetectionNotSeverity:
    """What the configuration actually says about the reported 100,000.

    There is no 100,000 in flood detection. The ICMP and UDP thresholds
    default to 120 and 300 packets per second and accept up to 1,000,000.
    The only settings bounded at 100,000 are the domain cache size, the
    packet-table row limit and the retained-notification count, none of
    which is a detection or severity threshold.
    """

    #: Settings whose input bound is 100,000 - none of them flood thresholds.
    UNRELATED_HUNDRED_THOUSAND = {
        "capture.domain_cache_entries",
        "ui.packet_table_max_rows",
        "notifications.max_retained",
    }

    def test_no_detection_setting_is_a_hundred_thousand(self) -> None:
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        for key, spec in SETTING_SPEC_BY_KEY.items():
            if not key.startswith("detection."):
                continue
            assert spec.default != 100_000, (
                f"{key} defaults to 100,000; the brief's figure would then be "
                "a real detection threshold"
            )

    def test_the_hundred_thousand_bound_belongs_elsewhere(self) -> None:
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        bounded = {
            key for key, spec in SETTING_SPEC_BY_KEY.items()
            if getattr(spec, "maximum", None) == 100_000
        }
        assert bounded == self.UNRELATED_HUNDRED_THOUSAND, (
            f"the settings bounded at 100,000 have changed: {sorted(bounded)}"
        )

    def test_the_rate_thresholds_are_detection_thresholds_in_pps(self) -> None:
        """Unit: packets per second, per source, over the rate window."""
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        for key, expected in (("detection.icmp_packets_per_second", 120),
                              ("detection.udp_packets_per_second", 300)):
            spec = SETTING_SPEC_BY_KEY[key]
            assert spec.default == expected
            assert spec.minimum == 1
            assert "second" in spec.description.lower()
        window = SETTING_SPEC_BY_KEY["detection.rate_window_seconds"]
        assert window.default == 5, "the measurement interval changed"

    def test_the_detection_default_is_far_below_the_medium_floor(self) -> None:
        """Which is why a real ICMP flood can be detected and still be LOW.

        The ICMP rule fires from its configured threshold upwards, and the
        severity bands start at 500. A ping flood between the two is a
        genuine detection that is genuinely LOW, and that is not a bug.
        """
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        icmp = SETTING_SPEC_BY_KEY["detection.icmp_packets_per_second"].default
        assert flood_severity(float(icmp))[0] is Severity.LOW

    def test_a_rate_of_one_hundred_thousand_would_be_high(self) -> None:
        """If a rate that high were ever measured, it classifies HIGH."""
        assert flood_severity(100_000.0)[0] is Severity.HIGH


# ---------------------------------------------------------------------------
# C - measurement scope: per protocol, per source, over the real window
# ---------------------------------------------------------------------------
class TestTheRateIsProtocolSpecific:
    def test_the_icmp_rule_divides_its_own_counter_by_the_window(self) -> None:
        from aethra_sec.analytics import anomaly_rules

        source = inspect.getsource(anomaly_rules.AnomalyRuleEngine._check_icmp)
        assert "self._icmp[source].add(timestamp, window)" in source
        assert "rate = count / float(window)" in source
        # The severity comes from that same measured rate, not from elsewhere.
        assert "flood_severity(rate)" in source

    def test_the_udp_rule_does_the_same(self) -> None:
        from aethra_sec.analytics import anomaly_rules

        source = inspect.getsource(anomaly_rules.AnomalyRuleEngine._check_udp)
        assert "/ float(window)" in source
        assert "flood_severity(rate)" in source

    def test_the_icmp_rule_states_its_scope_in_the_evidence(self) -> None:
        """So an operator can tell it apart from the Traffic Rate graph."""
        from aethra_sec.analytics import anomaly_rules

        source = inspect.getsource(anomaly_rules.AnomalyRuleEngine._check_icmp)
        assert "rate_scope" in source
        assert "Not " in source and "interface total" in source

    def test_severity_is_never_assigned_from_the_signature(self) -> None:
        from aethra_sec.analytics import anomaly_rules

        source = inspect.getsource(anomaly_rules)
        for wrong in ('if "ICMP" in', 'if "UDP" in', 'if "flood" in'):
            assert wrong not in source


# ---------------------------------------------------------------------------
# D - an episode's severity is raised, never lowered
# ---------------------------------------------------------------------------
class TestAnEpisodeSeverityIsNotLoweredByASlowerSample:
    """The confirmed cause of "still sometimes classified as LOW".

    Recorded example from the live data before the fix: anomaly 2356,
    RULE-UDP-RATE, observed 1,733.2 pps, latest 497.2 pps, severity LOW,
    peak HIGH.
    """

    def test_the_update_raises_both_severity_and_peak(self) -> None:
        from aethra_sec.database.repositories.alerts import AlertRepository

        source = inspect.getsource(AlertRepository.update_anomaly_occurrence)
        assert 'rise.format(column="severity")' in source, (
            "severity is not raised through the ladder"
        )
        assert 'rise.format(column="peak_severity")' in source
        assert "severity = %s, " not in source, (
            "severity is still being replaced outright"
        )

    def test_the_live_rate_is_still_recorded(self) -> None:
        """Raising the severity must not cost the current measurement."""
        from aethra_sec.database.repositories.alerts import AlertRepository

        source = inspect.getsource(AlertRepository.update_anomaly_occurrence)
        assert "latest_value = %s" in source
        assert "latest_measured_at = %s" in source
        assert "observed_value = GREATEST(observed_value, %s)" in source

    def test_the_fold_compares_against_the_previous_measurement(self) -> None:
        """Otherwise a steady flood writes the same transition row forever."""
        from aethra_sec.services.packet_capture import PacketCaptureService

        source = inspect.getsource(PacketCaptureService._fold_into_episode)
        assert 'getattr(existing, "latest_value", None)' in source
        assert "flood_severity(prior)" in source

    def test_escalation_is_judged_against_the_stored_severity(self) -> None:
        """So a rate that dips and recovers does not interrupt twice."""
        from aethra_sec.services.packet_capture import PacketCaptureService

        source = inspect.getsource(PacketCaptureService._fold_into_episode)
        assert "if current.rank > stored.rank:" in source

    def test_a_non_flood_rule_is_still_left_alone(self) -> None:
        """A port scan's severity is measured in ports, not packets."""
        from aethra_sec.services.packet_capture import PacketCaptureService

        source = inspect.getsource(PacketCaptureService._fold_into_episode)
        assert "if anomaly.rule_id not in FLOOD_RULES:" in source


# ---------------------------------------------------------------------------
# E - the live band stays visible beside the alert's severity
# ---------------------------------------------------------------------------
class TestTheCurrentBandIsStillShown:
    def test_a_falling_rate_is_reported_as_the_current_band(self) -> None:
        from aethra_sec.ui.screens.alerts import _current_band

        class _Episode:
            rule_id = "RULE-UDP-RATE"
            latest_value = 497.2

        assert _current_band(_Episode()) == str(Severity.LOW)

    def test_a_high_rate_reads_high(self) -> None:
        from aethra_sec.ui.screens.alerts import _current_band

        class _Episode:
            rule_id = "RULE-ICMP-RATE"
            latest_value = 1733.2

        assert _current_band(_Episode()) == str(Severity.HIGH)

    @pytest.mark.parametrize("rule,rate", [
        ("RULE-PORT-SCAN", 50.0),      # measured in ports, not packets
        ("RULE-HOST-SWEEP", 15.0),     # measured in hosts
        ("RULE-UDP-RATE", None),       # nothing measured yet
        ("RULE-UDP-RATE", 0.0),        # not a usable rate
    ])
    def test_nothing_is_invented_when_there_is_no_rate(
        self, rule: str, rate: float | None
    ) -> None:
        from aethra_sec.ui.screens.alerts import _current_band

        class _Episode:
            rule_id = rule
            latest_value = rate

        assert _current_band(_Episode()) == "-"


# ---------------------------------------------------------------------------
# F - the severity to level mapping, and therefore the sound
# ---------------------------------------------------------------------------
class TestSoundEligibilityIsConfigurable:
    """The confirmed cause of the silent popup.

    ``WARNING if severity is HIGH else INFO`` made a MEDIUM detection INFO,
    and with ``sound_min_level = WARNING`` that meant sound required HIGH.
    Measured on the live data before the fix: 48 anomaly notifications at
    INFO against 3 at WARNING.
    """

    @pytest.mark.parametrize("severity,level", [
        (Severity.INFO, NotificationLevel.INFO),
        (Severity.LOW, NotificationLevel.INFO),
        (Severity.MEDIUM, NotificationLevel.WARNING),
        (Severity.HIGH, NotificationLevel.ERROR),
        (Severity.CRITICAL, NotificationLevel.CRITICAL),
    ])
    def test_each_severity_maps_to_a_distinct_level(
        self, severity: Severity, level: NotificationLevel
    ) -> None:
        from aethra_sec.services.notification_service import level_for_severity

        assert level_for_severity(severity) is level

    def test_medium_no_longer_collapses_to_information(self) -> None:
        from aethra_sec.services.notification_service import level_for_severity

        assert level_for_severity(Severity.MEDIUM) is not NotificationLevel.INFO

    def test_an_unknown_severity_fails_towards_audible(self) -> None:
        from aethra_sec.services.notification_service import level_for_severity

        assert level_for_severity("nonsense") is NotificationLevel.WARNING

    def test_the_mapping_orders_the_way_the_audio_service_ranks(self) -> None:
        """The levels must be comparable on the audio service's own ladder."""
        from aethra_sec.services.audio_alert_service import _ORDER
        from aethra_sec.services.notification_service import level_for_severity

        ranks = [
            _ORDER.index(str(level_for_severity(s)))
            for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH,
                      Severity.CRITICAL)
        ]
        assert ranks == sorted(ranks), f"the mapping is not monotonic: {ranks}"

    def test_both_notifier_paths_use_the_one_mapping(self) -> None:
        """So the Snort path and the detection path cannot drift apart."""
        from aethra_sec.services import notification_service

        source = inspect.getsource(notification_service)
        assert source.count("level_for_severity(") >= 3  # helper + two callers
        assert "if alert.severity is Severity.HIGH" not in source
        assert "if severity is Severity.HIGH" not in source


# ---------------------------------------------------------------------------
# G - popup eligibility is independent of sound
# ---------------------------------------------------------------------------
class TestPopupAndSoundAreDecidedSeparately:
    def test_the_popup_does_not_consult_any_sound_setting(self) -> None:
        from aethra_sec.services import notification_service

        source = inspect.getsource(notification_service.NotificationService)
        start = source.index("notifications.min_severity")
        window = source[max(0, start - 400):start + 400]
        assert "sound" not in window.lower(), (
            "popup eligibility is entangled with a sound setting"
        )

    def test_severity_filtering_uses_the_ranking_not_equality(self) -> None:
        from aethra_sec.services import notification_service

        source = inspect.getsource(notification_service.NotificationService)
        assert "at_least(minimum)" in source

    def test_the_popup_is_raised_outside_the_audio_branch(self) -> None:
        """Turning sound off must not turn the popup off."""
        from aethra_sec.ui import app as app_module

        # The notification branch moved to its own handler so it could wait
        # in a buffer that packet traffic cannot fill.
        source = inspect.getsource(
            app_module.MainWindow._on_notification_event)
        guard = popup = None
        for line in source.splitlines():
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped.startswith("if audio is not None"):
                guard = indent
            elif "show_persistent" in stripped and popup is None:
                popup = indent
        assert guard is not None and popup is not None
        assert popup <= guard


# ---------------------------------------------------------------------------
# H - migration 26, and what it deliberately left alone
# ---------------------------------------------------------------------------
class TestThePeakCanNeverRankBelowTheSeverity:
    def test_the_migration_is_registered(self) -> None:
        from aethra_sec.database.migrations import LATEST_VERSION, MIGRATIONS

        names = {m.version: m.name for m in MIGRATIONS}
        assert names.get(26) == "peak_not_below_severity"
        assert LATEST_VERSION >= 26

    def test_it_raises_only_the_peak(self) -> None:
        """``severity`` must not be rewritten: the history to do it honestly
        was never stored for those rows."""
        from aethra_sec.database import migrations

        source = inspect.getsource(migrations._apply_peak_not_below_severity)
        assert "SET peak_severity = severity" in source
        assert "SET severity" not in source

    def test_it_is_idempotent(self) -> None:
        from aethra_sec.database import migrations

        source = inspect.getsource(migrations._apply_peak_not_below_severity)
        assert "if not affected:" in source
        assert "FIELD(peak_severity" in source and "< FIELD(severity" in source

    def test_the_model_floors_the_peak_at_the_current_severity(self) -> None:
        """Belt and braces for any row the migration has not reached."""
        from aethra_sec.models.threat import TrafficAnomaly

        anomaly = TrafficAnomaly(
            rule_id="RULE-UDP-RATE", severity=Severity.HIGH,
            peak_severity=Severity.LOW,
        )
        assert anomaly.highest_severity is Severity.HIGH
