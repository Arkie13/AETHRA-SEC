"""Make a silent detector explain itself.

Written after an ICMP flood test produced no alert and no notification, and
neither outcome was a defect: the traffic ran at about 100 packets per second
per source against a configured threshold of 120, and the Snort alert file
had not been written for ten and a half hours because the pcap feed behind
the sensor was not running. Both subsystems behaved correctly and said
nothing about it, which is why the cause took a forensic dig to establish.

These tests cover the two diagnostics added so the next silence answers for
itself. They raise no alert, write no record and change no threshold.

The packet rates below are test fixtures driving the detector in-process.
They are not observations of any network.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from aethra_sec.analytics.anomaly_rules import (
    NEAR_MISS_FRACTION,
    NEAR_MISS_INTERVAL_SECONDS,
    AnomalyRuleEngine,
    DetectionThresholds,
)

from conftest import make_packet

#: The thresholds this deployment actually runs, so the scenarios below are
#: the reported ones rather than invented numbers.
LIVE = DetectionThresholds(
    icmp_per_second=120, udp_per_second=300, syn_per_second=200,
    http_per_second=10, rate_window=5,
)


def _flood(engine: AnomalyRuleEngine, pps: float, seconds: float = 6.0,
           src: str = "198.51.100.9", dst: str = "198.51.100.1") -> list:
    """Drive the engine at a steady ICMP rate and collect what it raises."""
    raised = []
    for index in range(int(pps * seconds)):
        packet = make_packet(
            src_ip=src, dst_ip=dst, protocol="ICMP", length=98,
            src_port=None, dst_port=None, tcp_flags=None,
            offset_seconds=index / pps,
        )
        raised.extend(engine.evaluate(packet))
    return raised


# ---------------------------------------------------------------------------
# The reported scenario, end to end through the real rule
# ---------------------------------------------------------------------------
class TestTheReportedScenario:
    def test_one_hundred_pps_against_a_one_twenty_threshold_raises_nothing(
        self,
    ) -> None:
        """The measured reason there was no alert, not a guess at it."""
        raised = _flood(AnomalyRuleEngine(LIVE), pps=100)
        assert raised == [], (
            "traffic below the configured threshold must not raise an alert"
        )

    def test_the_rate_that_did_fire_still_fires(self) -> None:
        """The earlier test ran at ~350 pps per source and was detected."""
        raised = _flood(AnomalyRuleEngine(LIVE), pps=350)
        assert raised, "a flood above the threshold stopped being detected"
        assert raised[0].rule_id == "RULE-ICMP-RATE"
        assert raised[0].threshold_value == 120.0

    def test_the_threshold_is_per_source_not_per_interface(self) -> None:
        """Two hosts at 100 pps each do not add up to one detection.

        A ping flood is counted once from the attacker and again from the
        replying host, so the Traffic Rate graph reads about double the
        figure the rule compares. That is why a graph showing 200 pps
        corresponds to 100 pps per source and raises nothing here.
        """
        engine = AnomalyRuleEngine(LIVE)
        raised = _flood(engine, pps=100, src="198.51.100.9",
                        dst="198.51.100.1")
        raised += _flood(engine, pps=100, src="198.51.100.1",
                         dst="198.51.100.9")
        assert raised == []


# ---------------------------------------------------------------------------
# The near-miss diagnostic
# ---------------------------------------------------------------------------
class TestANearMissIsVisible:
    def test_traffic_close_to_the_threshold_is_logged(self, caplog) -> None:
        with caplog.at_level(logging.INFO):
            _flood(AnomalyRuleEngine(LIVE), pps=100)
        lines = [r.getMessage() for r in caplog.records if "NEAR-MISS" in r.getMessage()]
        assert lines, "a flood just below the threshold explained nothing"
        message = lines[0]
        assert "RULE-ICMP-RATE" in message
        assert "120.0" in message, "the threshold it was compared against"
        assert "packets/second" in message, "the unit of the measurement"

    def test_quiet_traffic_is_not_logged(self, caplog) -> None:
        """Below the fraction there is nothing interesting to say."""
        quiet = LIVE.icmp_per_second * NEAR_MISS_FRACTION * 0.4
        with caplog.at_level(logging.INFO):
            _flood(AnomalyRuleEngine(LIVE), pps=max(2.0, quiet))
        assert not [r for r in caplog.records if "NEAR-MISS" in r.getMessage()]

    def test_a_sustained_flood_does_not_flood_the_log(self, caplog) -> None:
        """One line a minute per source, not one per packet."""
        with caplog.at_level(logging.INFO):
            _flood(AnomalyRuleEngine(LIVE), pps=100, seconds=20)
        lines = [r for r in caplog.records if "NEAR-MISS" in r.getMessage()]
        assert len(lines) <= 2, (
            f"{len(lines)} near-miss lines for a 20-second flood; the rate "
            "limit is not holding"
        )

    def test_the_rate_limit_is_per_source(self) -> None:
        engine = AnomalyRuleEngine(LIVE)
        engine._note_near_miss("RULE-ICMP-RATE|a", 100.0, 120.0, 1000.0)
        engine._note_near_miss("RULE-ICMP-RATE|b", 100.0, 120.0, 1000.0)
        assert set(engine._near_miss) == {"RULE-ICMP-RATE|a", "RULE-ICMP-RATE|b"}

    def test_the_interval_is_respected(self) -> None:
        engine = AnomalyRuleEngine(LIVE)
        engine._note_near_miss("m", 100.0, 120.0, 1000.0)
        first = engine._near_miss["m"]
        engine._note_near_miss("m", 100.0, 120.0, 1000.0 + 5)
        assert engine._near_miss["m"] == first, "logged again too soon"
        engine._note_near_miss(
            "m", 100.0, 120.0, 1000.0 + NEAR_MISS_INTERVAL_SECONDS + 1)
        assert engine._near_miss["m"] > first

    def test_it_raises_nothing_at_all(self) -> None:
        """A diagnostic must never become a detection."""
        engine = AnomalyRuleEngine(LIVE)
        before = dict(engine._near_miss)
        result = engine._note_near_miss("m", 100.0, 120.0, 1000.0)
        assert result is None
        assert engine._near_miss != before  # it only recorded the log time

    def test_a_zero_threshold_cannot_divide_or_log(self) -> None:
        engine = AnomalyRuleEngine(LIVE)
        engine._note_near_miss("m", 100.0, 0.0, 1000.0)
        assert engine._near_miss == {}


# ---------------------------------------------------------------------------
# The silent alert source
# ---------------------------------------------------------------------------
class TestASilentAlertSourceIsReported:
    """"RUNNING" meant the file opened, not that the sensor was alive.

    The alert file had been untouched for ten and a half hours while the
    screen showed a healthy green transport line.
    """

    def test_the_transport_reports_the_age_of_its_file(self, tmp_path) -> None:
        from aethra_sec.integrations.snort.transports import AlertFileTransport

        path = tmp_path / "alert"
        path.write_text("", encoding="utf-8")
        transport = AlertFileTransport.__new__(AlertFileTransport)
        transport._path = path
        age = transport.source_age_seconds()
        assert age is not None and age < 60

    def test_a_missing_file_reports_unknown_rather_than_zero(
        self, tmp_path
    ) -> None:
        from aethra_sec.integrations.snort.transports import AlertFileTransport

        transport = AlertFileTransport.__new__(AlertFileTransport)
        transport._path = tmp_path / "does-not-exist"
        assert transport.source_age_seconds() is None

    def test_an_old_file_is_called_out_on_the_status_line(
        self, tmp_path
    ) -> None:
        from aethra_sec.ui.screens.alerts import _source_silence_note

        class _Transport:
            def source_age_seconds(self):
                return 10.5 * 3600

        class _Snort:
            _transport = _Transport()

        note = _source_silence_note(_Snort())
        assert "NO NEW ALERTS FOR" in note
        assert "10h 30m" in note
        assert "nothing is writing to it" in note

    def test_a_live_file_is_not_called_out(self) -> None:
        from aethra_sec.ui.screens.alerts import _source_silence_note

        class _Transport:
            def source_age_seconds(self):
                return 12.0

        class _Snort:
            _transport = _Transport()

        note = _source_silence_note(_Snort())
        assert "NO NEW ALERTS" not in note
        assert "12s ago" in note

    @pytest.mark.parametrize("transport", [None, object()])
    def test_a_transport_without_a_file_says_nothing(self, transport) -> None:
        """A socket or syslog transport has no file age to report."""
        from aethra_sec.ui.screens.alerts import _source_silence_note

        class _Snort:
            _transport = None

        snort = _Snort()
        snort._transport = transport
        assert _source_silence_note(snort) == ""

    def test_a_failing_probe_never_breaks_the_screen(self) -> None:
        from aethra_sec.ui.screens.alerts import _source_silence_note

        class _Transport:
            def source_age_seconds(self):
                raise OSError("disk went away")

        class _Snort:
            _transport = _Transport()

        assert _source_silence_note(_Snort()) == ""


# ---------------------------------------------------------------------------
# File tailing: appended content must be picked up (section 12.C)
# ---------------------------------------------------------------------------
class TestAppendedAlertsAreDetected:
    def test_the_reader_starts_at_the_end_not_the_beginning(self) -> None:
        """A 95 MB historical file must not be replayed on connect."""
        import inspect

        from aethra_sec.integrations.snort.transports import AlertFileTransport

        source = inspect.getsource(AlertFileTransport._open)
        assert "handle.seek(0, os.SEEK_END)" in source

    def test_rotation_and_truncation_reopen_the_file(self) -> None:
        import inspect

        from aethra_sec.integrations.snort.transports import AlertFileTransport

        source = inspect.getsource(AlertFileTransport._check_rotation)
        assert "st_ino != self._inode" in source, "rotation is not detected"
        assert "stat.st_size < handle.tell()" in source, (
            "truncation is not detected"
        )

    def test_an_appended_line_is_parsed_and_emitted(self) -> None:
        """The parser accepts the real alert_fast format this sensor writes."""
        from aethra_sec.integrations.snort.parser import parse_alert_line

        line = (
            "10/13-15:09:12.123456  [**] [1:1000006:2] "
            "ICMP flood - possible ping flood/DoS [**] "
            "[Classification: Attempted Denial of Service] [Priority: 2] "
            "{ICMP} 192.168.0.104 -> 192.168.0.105"
        )
        alert = parse_alert_line(line, None)
        assert alert is not None, "a real alert_fast line failed to parse"
        assert alert.src_ip == "192.168.0.104"
        assert alert.dst_ip == "192.168.0.105"
        assert "ICMP flood" in alert.message or "ICMP flood" in str(alert)

    def test_a_blank_or_comment_line_is_ignored_without_a_failure(self) -> None:
        from aethra_sec.integrations.snort.parser import parse_alert_line

        for noise in ("", "   ", "#comment"):
            assert parse_alert_line(noise, None) is None
