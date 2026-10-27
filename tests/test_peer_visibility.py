"""Whether other devices are observable is answered from frames, not hope.

The question "why does Live Monitoring not show the other device" has four
possible answers and only one of them is a bug in this application. Measured on
this machine over a real 45-second capture, the counts were

    captured 2,109 -> parsed 2,109 -> displayed 2,109

so nothing was dropped by the parser and nothing hidden by a filter, while
peer unicast frames were zero and eight other devices were nonetheless present
(their broadcast traffic arrived). Windows reports the adapter's promiscuous
mode as "Not Supported", which is why.

These tests hold the reasoning that produced that verdict, because every step
of it is easy to get subtly wrong - and I got two of them wrong before they
were written:

* broadcast and multicast are flooded to every station, so counting them as
  peer traffic invents visibility. An early version missed IP multicast and
  reported nine SSDP frames as peer unicast;
* "this host" must be decided by the same local-address view the direction
  column uses, or the two disagree. An early diagnostic used a hardcoded
  address that had gone stale and classified 1,777 of the host's own frames
  as another device's;
* a device seen only via broadcast is present but not observable, and saying
  so is the strongest honest statement available;
* capability is read from the driver, never inferred from the adapter's name.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.analytics import adapter_capability as cap
from aethra_sec.analytics.peer_visibility import (
    NOT_VISIBLE,
    OBSERVATION_POINT_ADVICE,
    PROMISCUOUS_VS_MIRRORING,
    VISIBILITY_THRESHOLD,
    PeerVisibilityTracker,
)


class _Local:
    """Stands in for LocalAddresses: only is_local is read."""

    def __init__(self, *addresses: str) -> None:
        self._addresses = set(addresses)

    def is_local(self, address: str) -> bool:
        return address in self._addresses


class _Packet:
    def __init__(self, src="", dst="", dst_mac="") -> None:  # noqa: ANN001
        self.src_ip = src
        self.dst_ip = dst
        self.dst_mac = dst_mac


ME = _Local("192.168.100.31")


# ---------------------------------------------------------------------------
# What counts as peer traffic
# ---------------------------------------------------------------------------
class TestCounting:
    def test_our_own_traffic_is_not_peer_traffic(self) -> None:
        tracker = PeerVisibilityTracker()
        for _ in range(20):
            tracker.observe(_Packet("192.168.100.31", "93.184.216.34", "aa:bb:cc:dd:ee:ff"), ME)
        report = tracker.report()
        assert report.own_frames == 20
        assert report.peer_frames == 0
        assert not report.peer_traffic_visible

    def test_incoming_traffic_to_us_is_also_ours(self) -> None:
        tracker = PeerVisibilityTracker()
        tracker.observe(_Packet("93.184.216.34", "192.168.100.31", "aa:bb:cc:dd:ee:ff"), ME)
        assert tracker.report().own_frames == 1

    def test_real_peer_unicast_is_counted(self) -> None:
        tracker = PeerVisibilityTracker()
        for _ in range(VISIBILITY_THRESHOLD):
            tracker.observe(
                _Packet("192.168.100.55", "142.250.1.1", "aa:bb:cc:11:22:33"), ME
            )
        report = tracker.report()
        assert report.peer_frames == VISIBILITY_THRESHOLD
        assert report.peer_traffic_visible
        assert "Peer traffic IS visible" in report.verdict()

    @pytest.mark.parametrize(
        "destination,mac",
        [
            ("239.255.255.250", "01:00:5e:7f:ff:fa"),   # SSDP, IP multicast
            ("224.0.0.251", "01:00:5e:00:00:fb"),       # mDNS
            ("255.255.255.255", "ff:ff:ff:ff:ff:ff"),   # broadcast
            ("192.168.100.255", "ff:ff:ff:ff:ff:ff"),   # directed broadcast
            ("239.255.255.250", ""),                    # no MAC: IP alone decides
        ],
    )
    def test_broadcast_and_multicast_are_never_peer_traffic(
        self, destination: str, mac: str
    ) -> None:
        """Flooded to every station by design; counting it invents visibility."""
        tracker = PeerVisibilityTracker()
        for _ in range(10):
            tracker.observe(_Packet("192.168.100.55", destination, mac), ME)
        report = tracker.report()
        assert report.peer_frames == 0
        assert report.group_frames == 10

    def test_a_multicast_only_device_is_present_but_invisible(self) -> None:
        """The strongest honest statement: it is here, and unreadable."""
        tracker = PeerVisibilityTracker()
        for _ in range(6):
            tracker.observe(
                _Packet("192.168.100.55", "239.255.255.250", "01:00:5e:7f:ff:fa"), ME
            )
        report = tracker.report()
        assert report.group_only_hosts == 1
        assert report.peers_exist_but_are_invisible
        assert NOT_VISIBLE in report.verdict()
        assert "present on this network" in report.verdict()

    def test_a_device_later_seen_by_unicast_stops_being_invisible(self) -> None:
        tracker = PeerVisibilityTracker()
        tracker.observe(
            _Packet("192.168.100.55", "239.255.255.250", "01:00:5e:7f:ff:fa"), ME
        )
        assert tracker.report().group_only_hosts == 1
        for _ in range(VISIBILITY_THRESHOLD):
            tracker.observe(_Packet("192.168.100.55", "8.8.8.8", "aa:bb:cc:11:22:33"), ME)
        report = tracker.report()
        assert report.group_only_hosts == 0
        assert report.peer_traffic_visible

    def test_one_stray_frame_is_not_visibility(self) -> None:
        tracker = PeerVisibilityTracker()
        tracker.observe(_Packet("10.0.0.5", "10.0.0.6", "aa:bb:cc:11:22:33"), ME)
        assert not tracker.report().peer_traffic_visible

    def test_nothing_captured_says_so_rather_than_claiming_a_limitation(self) -> None:
        assert "No frames" in PeerVisibilityTracker().report().verdict()


# ---------------------------------------------------------------------------
# Bounded
# ---------------------------------------------------------------------------
class TestItIsBounded:
    def test_the_tracked_sets_are_capped(self) -> None:
        tracker = PeerVisibilityTracker(max_tracked=32)
        for n in range(4000):
            tracker.observe(
                _Packet(f"10.0.{n // 256}.{n % 256}", "8.8.8.8", "aa:bb:cc:11:22:33"),
                ME,
            )
        report = tracker.report()
        assert report.peer_hosts <= 32
        assert report.peer_frames == 4000, "frames are counted even when hosts are not"

    def test_the_hot_path_takes_one_lock(self) -> None:
        body = inspect.getsource(PeerVisibilityTracker.observe)
        assert body.count("with self._lock") == 1


# ---------------------------------------------------------------------------
# It counts packets, not database rows
# ---------------------------------------------------------------------------
class TestItUsesPacketsNotTheDatabase:
    def test_the_module_never_reads_the_database(self) -> None:
        """§3: a host in the Hosts table was seen once; that is not visibility."""
        import aethra_sec.analytics.peer_visibility as module

        source = inspect.getsource(module)
        for forbidden in ("SELECT", "repository", "db.", "HostRepository"):
            assert forbidden not in source

    def test_the_view_feeds_it_with_the_same_local_addresses_as_direction(self) -> None:
        """Two answers to "which host is this" would contradict each other."""
        from aethra_sec.services import packet_view

        body = inspect.getsource(packet_view.PacketView.step)
        assert "self.visibility.observe(packet, local)" in body
        assert "classify(packet, local)" in body


# ---------------------------------------------------------------------------
# The distinction that causes the confusion
# ---------------------------------------------------------------------------
class TestTheDistinctionIsDocumented:
    def test_promiscuous_is_distinguished_from_mirroring(self) -> None:
        text = PROMISCUOUS_VS_MIRRORING.lower()
        assert "promiscuous" in text and ("mirror" in text or "span" in text)
        assert "cannot" in text

    def test_the_advice_is_about_the_network_not_the_application(self) -> None:
        text = OBSERVATION_POINT_ADVICE.lower()
        assert "span" in text or "mirroring" in text
        assert "tap" in text
        assert "gateway" in text or "router" in text


# ---------------------------------------------------------------------------
# Adapter capability comes from the driver
# ---------------------------------------------------------------------------
class TestAdapterCapability:
    def test_capability_is_never_inferred_from_the_adapter_name(self) -> None:
        """"Wi-Fi 6" says nothing about whether the driver exposes raw frames."""
        source = inspect.getsource(cap)
        assert "netsh" in source
        assert "wirelesscapabilities" in source

    def test_it_never_changes_the_adapter_state(self) -> None:
        """Enabling monitor mode would drop the operator's own connection.

        Checked against the code with its prose removed: this module's
        docstring discusses disconnection at length, so a plain substring
        search over the file passes on the explanation alone.
        """
        source = inspect.getsource(cap)
        for block in (cap.__doc__ or "", cap.AdapterCapability.limitation.__doc__ or "",
                      cap.probe.__doc__ or ""):
            for line in block.splitlines():
                source = source.replace(line, "")
        # The only subprocess call must be the read-only capability query.
        assert source.count("subprocess.run") == 1
        assert '"netsh", "wlan", "show", "wirelesscapabilities"' in source
        for forbidden in ("wlan connect", "wlan disconnect", "mode=monitor",
                          "set profile", "set hostednetwork"):
            assert forbidden not in source

    @pytest.mark.parametrize(
        "value,expected",
        [("Not Supported", False), ("Not supported", False),
         ("Supported", True), ("", None), ("who knows", None)],
    )
    def test_the_platform_answer_is_parsed_not_guessed(self, value, expected) -> None:  # noqa: ANN001
        assert cap._as_bool(value) is expected

    def test_an_unsupported_wireless_adapter_states_the_limitation(self) -> None:
        capability = cap.AdapterCapability(
            interface_type="Wi-Fi", promiscuous="Not Supported",
            monitor_mode="Not supported",
        )
        limitation = capability.limitation()
        assert "does not provide the required peer-device visibility" in limitation

    def test_a_capable_adapter_claims_no_limitation(self) -> None:
        capability = cap.AdapterCapability(
            interface_type="Wi-Fi", promiscuous="Supported", monitor_mode="Supported"
        )
        assert capability.limitation() == ""

    def test_a_wired_adapter_is_not_asked_the_wireless_question(self) -> None:
        capability = cap.probe("Realtek PCIe GbE Family Controller", "Ethernet")
        assert capability.interface_type == "Ethernet"
        assert capability.promiscuous == cap.UNKNOWN, (
            "answering for a wired adapter from the wireless query would be a "
            "guess presented as a driver report"
        )
        assert "switch" in capability.detail.lower()


# ---------------------------------------------------------------------------
# The capture command asks for promiscuous mode
# ---------------------------------------------------------------------------
class TestTheCaptureAsksForIt:
    def test_the_reader_never_disables_promiscuous_mode(self) -> None:
        """§2: -p is --no-promiscuous-mode. It must never be passed."""
        from aethra_sec.integrations.pyshark_capture.field_reader import (
            FieldCaptureReader,
        )

        body = inspect.getsource(FieldCaptureReader._command)
        assert '"-p"' not in body
        assert "no-promiscuous" not in body

    def test_the_diagnostic_reports_both_capability_rows(self) -> None:
        from aethra_sec.services import capture_diagnostic

        body = inspect.getsource(capture_diagnostic.CaptureDiagnostic.lines)
        assert "Promiscuous mode" in body
        assert "Monitor mode" in body

    def test_the_diagnostic_reports_observed_hosts_from_packets(self) -> None:
        from aethra_sec.services import capture_diagnostic

        body = inspect.getsource(capture_diagnostic.CaptureDiagnostic.lines)
        assert "Observed local hosts" in body
        assert "Observed non-local hosts" in body
        assert "Peer unicast frames" in body
