"""The diagnostic separates "we discarded it" from "it never arrived".

Those two look identical in the packet table and have opposite remedies. The
first is a bug in this application; the second is where the sensor is attached,
and no change here can fix it. Measured on this machine, it was the second:
thirty seconds of promiscuous capture on the real Wi-Fi interface produced 580
frames, of which zero were peer-to-peer unicast.

So the report states three counts from three different stages and never derives
one from another, and it says out loud what a wireless capture point cannot
see. These tests hold both, plus the rule that matters most for trust: a value
that could not be read is reported as unknown, never as a plausible number.
"""

from __future__ import annotations

import pytest

from aethra_sec.services import capture_diagnostic as cd


class _ViewStatistics:
    def __init__(self, matched: int = 0, expression: str = "") -> None:
        self.matched = matched
        self.expression = expression


class _View:
    """Mirrors PacketView: the counts come from statistics(), not attributes."""

    def __init__(self, matched: int = 0, expression: str = "") -> None:
        self._statistics = _ViewStatistics(matched, expression)

    def statistics(self) -> _ViewStatistics:
        return self._statistics


class _Stats:
    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        self.total_packets = kwargs.get("total_packets", 0)
        self.dropped = kwargs.get("dropped", 0)
        self.decode_errors = kwargs.get("decode_errors", 0)
        self.sampled_out = kwargs.get("sampled_out", 0)
        self.bpf_filter = kwargs.get("bpf_filter", "")
        self.state = kwargs.get("state", "CAPTURING")


class _Counters:
    def __init__(self, processed: int = 0) -> None:
        self._processed = processed

    def snapshot(self) -> dict:
        return {"processed": self._processed}


class _Interface:
    def __init__(self, name: str, description: str, ipv4: str) -> None:
        self.name = name
        self.description = description
        self.primary_ipv4 = ipv4


class _Capture:
    """Only what the diagnostic reads."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        self.interface = kwargs.get("interface", "\\Device\\NPF_{ABC}")
        self._stats = _Stats(**kwargs.get("stats", {}))
        self.counters = _Counters(kwargs.get("processed", 0))
        self.view = _View(kwargs.get("matched", 0), kwargs.get("expression", ""))
        self.domains = kwargs.get("domains", [])
        self._pid = kwargs.get("pid", None)
        self._interfaces = kwargs.get("interfaces", [])

    def statistics(self):  # noqa: ANN201
        return self._stats

    def list_interfaces(self):  # noqa: ANN201
        return self._interfaces

    def reader_pid(self):  # noqa: ANN201
        return self._pid


# ---------------------------------------------------------------------------
# Three counts, three stages
# ---------------------------------------------------------------------------
class TestTheThreeCounts:
    def test_captured_parsed_and_displayed_come_from_different_sources(self) -> None:
        capture = _Capture(stats={"total_packets": 1000}, processed=950, matched=900)
        report = cd.build(capture)
        assert report.counts.captured == 1000
        assert report.counts.parsed == 950
        assert report.counts.displayed == 900

    def test_a_decode_gap_is_reported_as_a_gap(self) -> None:
        report = cd.build(_Capture(stats={"total_packets": 100}, processed=80))
        assert report.counts.decode_gap == 20

    def test_filtering_is_not_counted_as_loss(self) -> None:
        """Parsed-minus-displayed is a filter doing its job."""
        report = cd.build(
            _Capture(stats={"total_packets": 100}, processed=100, matched=10)
        )
        assert report.counts.filtered_out == 90
        assert report.counts.decode_gap == 0

    def test_displayed_is_never_inferred_from_captured(self) -> None:
        report = cd.build(_Capture(stats={"total_packets": 500}, processed=0, matched=0))
        assert report.counts.displayed == 0, (
            "a displayed figure derived from captured would hide the stage "
            "that actually lost the packets"
        )

    def test_a_decode_gap_is_named_as_an_application_problem(self) -> None:
        report = cd.build(_Capture(stats={"total_packets": 100}, processed=40))
        assert any("not parsed" in note for note in report.notes)

    def test_drops_are_attributed_to_the_capture_engine(self) -> None:
        report = cd.build(_Capture(stats={"total_packets": 100, "dropped": 7}))
        note = next(n for n in report.notes if "dropped" in n)
        assert "TShark's own" in note and "not inferred" in note


# ---------------------------------------------------------------------------
# Nothing is invented
# ---------------------------------------------------------------------------
class TestNothingIsInvented:
    def test_an_absent_pid_is_unknown_not_zero(self) -> None:
        report = cd.build(_Capture(pid=None))
        assert report.tshark_pid == cd.UNKNOWN

    def test_a_running_capture_reports_its_real_pid(self) -> None:
        assert cd.build(_Capture(pid=4242)).tshark_pid == "4242"

    def test_an_unmatched_interface_is_unknown_not_guessed(self) -> None:
        report = cd.build(_Capture(interface="\\Device\\NPF_{X}", interfaces=[]))
        assert report.interface_description == cd.UNKNOWN
        assert report.local_ipv4 == cd.UNKNOWN

    def test_a_subnet_is_only_reported_when_the_address_is_in_one(self) -> None:
        capture = _Capture(
            interface="if0",
            interfaces=[_Interface("if0", "Wi-Fi", "203.0.113.9")],
        )
        assert cd.build(capture).subnet == cd.UNKNOWN

    def test_no_capture_service_still_produces_a_report(self) -> None:
        report = cd.build(None)
        assert report.status == "capture service unavailable"
        assert cd.VISIBILITY_LIMITATION in report.notes

    def test_every_labelled_line_has_a_value(self) -> None:
        for label, value in cd.build(_Capture()).lines():
            assert label and value != "", f"{label} rendered empty"


# ---------------------------------------------------------------------------
# The limitation is stated, not hidden
# ---------------------------------------------------------------------------
class TestTheLimitationIsStated:
    def test_the_limitation_is_always_present(self) -> None:
        assert cd.VISIBILITY_LIMITATION in cd.build(_Capture()).notes

    def test_it_names_the_real_remedies(self) -> None:
        text = cd.VISIBILITY_LIMITATION.lower()
        assert "gateway" in text
        assert "span" in text or "mirroring" in text
        assert "tap" in text

    def test_it_does_not_promise_whole_network_visibility(self) -> None:
        text = cd.VISIBILITY_LIMITATION.lower()
        assert "only traffic delivered to the selected capture interface" in text

    @pytest.mark.parametrize(
        "description",
        ["Wi-Fi", "Intel Wireless-AC 9560", "Killer(R) Wi-Fi 6 AX1650i", "WLAN pseudo"],
    )
    def test_a_wireless_adapter_gets_the_wireless_note(self, description: str) -> None:
        capture = _Capture(
            interface="if0", interfaces=[_Interface("if0", description, "10.0.0.2")]
        )
        report = cd.build(capture)
        assert report.is_wireless
        assert cd.WIRELESS_NOTE in report.notes

    def test_a_wired_adapter_does_not_get_it(self) -> None:
        capture = _Capture(
            interface="if0",
            interfaces=[_Interface("if0", "Realtek PCIe GbE Family Controller", "10.0.0.2")],
        )
        report = cd.build(capture)
        assert not report.is_wireless
        assert cd.WIRELESS_NOTE not in report.notes

    def test_the_wireless_note_explains_pairwise_encryption(self) -> None:
        """Monitor mode would not help either; saying so prevents a wild goose
        chase through Npcap settings."""
        assert "pairwise key" in cd.WIRELESS_NOTE
        assert "managed mode" in cd.WIRELESS_NOTE


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------
class TestItSurvivesPartialState:
    def test_a_service_that_raises_still_yields_a_report(self) -> None:
        class Broken:
            interface = "if0"

            def statistics(self):  # noqa: ANN201
                raise RuntimeError("no")

            def list_interfaces(self):  # noqa: ANN201
                raise RuntimeError("no")

            def reader_pid(self):  # noqa: ANN201
                raise RuntimeError("no")

        report = cd.build(Broken())
        assert report.tshark_pid == cd.UNKNOWN
        assert cd.VISIBILITY_LIMITATION in report.notes

    def test_the_filters_default_to_readable_text_not_blank(self) -> None:
        rendered = dict(cd.build(_Capture()).lines())
        assert rendered["Capture filter"] == "(none - all traffic)"
        assert rendered["Display filter"] == "(none - all packets)"


# ---------------------------------------------------------------------------
# The service exposes what the report needs
# ---------------------------------------------------------------------------
class TestTheServiceSuppliesIt:
    def test_the_capture_service_exposes_the_reader_pid(self) -> None:
        from aethra_sec.services.packet_capture import PacketCaptureService

        assert hasattr(PacketCaptureService, "reader_pid")

    def test_a_stopped_reader_reports_no_pid(self) -> None:
        """A remembered number would still look alive after the child exited."""
        import inspect

        from aethra_sec.integrations.pyshark_capture import field_reader

        body = inspect.getsource(field_reader.FieldCaptureReader.pid.fget)
        assert "poll() is not None" in body

    def test_the_capture_service_owns_a_domain_resolver(self) -> None:
        import inspect

        from aethra_sec.services import packet_capture

        body = inspect.getsource(packet_capture.PacketCaptureService.__init__)
        assert "DomainResolver(" in body
