"""An anomaly must delimit its own evidence (§62).

A detection says "300 packets from this source in 5 seconds". The analyst's
next question is "show me those packets", and the only thing that can answer it
is the window the rule counted over. Both bounds were previously set to the
triggering packet's timestamp, which made the window a point: 1,138 of 1,148
stored anomalies had first_seen equal to last_seen, and a query bounded by them
returned one packet out of hundreds.

The same defect produced anomalies whose creation time preceded their own
first_seen - 15 rows in the live database - because the packet clock and the
system clock are not the same clock, and with a zero-width window that skew was
all there was.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aethra_sec.analytics.anomaly_rules import AnomalyRuleEngine, thresholds_from_settings
from aethra_sec.models.traffic import CapturedPacket


def _packet(when: datetime, **overrides) -> CapturedPacket:
    fields = {
        "captured_at": when,
        "src_ip": "192.0.2.10",
        "dst_ip": "192.0.2.20",
        "protocol": "UDP",
        "dst_port": 9999,
        "length": 64,
        "interface": "test",
    }
    fields.update(overrides)
    return CapturedPacket(**fields)


class TestTheWindowIsAnInterval:
    """first_seen and last_seen must bound the counted traffic."""

    def _fire_udp(self):
        """Drive the real engine past the UDP rate threshold."""
        settings = {
            "detection.udp_packets_per_second": 5,
            "detection.rate_window_seconds": 5,
        }
        engine = AnomalyRuleEngine()
        engine.update_thresholds(
            thresholds_from_settings(lambda k, d: settings.get(k, d))
        )
        start = datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC)
        raised = []
        for index in range(60):
            found = engine.evaluate(
                _packet(start + timedelta(milliseconds=index * 20))
            )
            raised.extend(found or [])
        return raised

    def test_a_rate_rule_reports_a_span_not_an_instant(self) -> None:
        raised = self._fire_udp()
        assert raised, "the engine did not fire on traffic above the threshold"
        anomaly = raised[0]
        assert anomaly.last_seen > anomaly.first_seen, (
            "the stored window is a point and cannot delimit its own evidence"
        )

    def test_the_span_matches_the_rule_window(self) -> None:
        raised = self._fire_udp()
        anomaly = raised[0]
        span = (anomaly.last_seen - anomaly.first_seen).total_seconds()
        assert span == anomaly.window_seconds, (
            f"window spans {span}s but the rule counted over "
            f"{anomaly.window_seconds}s"
        )

    def test_the_event_count_reflects_what_was_counted(self) -> None:
        """event_count was hard-coded to 1 whatever the observed value."""
        raised = self._fire_udp()
        anomaly = raised[0]
        assert anomaly.event_count == int(anomaly.observed_value), (
            f"counted {anomaly.observed_value} but recorded "
            f"event_count={anomaly.event_count}"
        )

    def test_the_window_precedes_the_trigger(self) -> None:
        """A detection cannot begin after the packet that triggered it."""
        raised = self._fire_udp()
        anomaly = raised[0]
        assert anomaly.first_seen < anomaly.last_seen
        assert anomaly.observed_value >= anomaly.threshold_value
