"""The Live Packets filter bar, end to end: thirteen views over real evidence.

Every preset on the bar is written in Wireshark display-filter syntax but is
evaluated locally, against the summary fields the live reader extracts rather
than against a full dissection. That is the right design for the hot path and
it is also where a filter can quietly disagree with the tool it imitates.

So the predicates were cross-checked against TShark's own answer on 11,637
real packets. Seven of nine protocol presets matched frame for frame. The two
that did not are both recorded below, because both are easy to "fix" into
something worse:

* **Sites** matched 4 fewer frames than TShark. The frames were SSDP. SSDP
  reuses HTTP's header syntax, so TShark's ``http.host`` field is populated by
  the SSDP dissector with ``239.255.255.250:1900`` - a multicast discovery
  address, not a site. This application scopes ``http.host`` to the HTTP layer
  and therefore excludes it. **The application is more correct than the raw
  TShark count, and these tests lock that in.**
* **DNS** appeared to match one frame more. It did not: the first measurement
  compared counts over two different frame sets. Re-run with the sets
  intersected, DNS matched 44 of 44 exactly.

The rest of the file holds what the cross-check could not: that a filter is a
*display* filter and never touches capture, that selecting one replaces the
previous rather than stacking, that captured and displayed stay separate
counters, and that odd packets do not raise.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.analytics.display_filter import (
    PROTOCOL_BY_KEY,
    FilterRequest,
    compile_filter,
    compose_filter,
    protocol_present,
)


class _Packet:
    """Only the attributes the filter language reads."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        self.layers: tuple[str, ...] = tuple(kwargs.pop("layers", ()))
        self.protocol: str = kwargs.pop("protocol", "")
        self.src_ip = kwargs.pop("src_ip", "")
        self.dst_ip = kwargs.pop("dst_ip", "")
        self.src_port = kwargs.pop("src_port", None)
        self.dst_port = kwargs.pop("dst_port", None)
        self.direction = kwargs.pop("direction", "")
        self.tls_sni = kwargs.pop("tls_sni", "")
        self.http_host = kwargs.pop("http_host", "")
        self.dns_query = kwargs.pop("dns_query", "")
        self.dns_response = kwargs.pop("dns_response", None)
        for key, value in kwargs.items():
            setattr(self, key, value)


def matches(key: str, packet: _Packet) -> bool:
    return compile_filter(PROTOCOL_BY_KEY[key].expression).matches(packet)


# ---------------------------------------------------------------------------
# Protocol views decide on decoded evidence, never on a port
# ---------------------------------------------------------------------------
class TestEvidenceNotPorts:
    def test_http_is_not_assumed_from_port_80(self) -> None:
        """TCP/80 carrying no decoded HTTP is not HTTP."""
        packet = _Packet(layers=("ETH", "IP", "TCP"), protocol="TCP", dst_port=80)
        assert not matches("HTTP", packet)

    def test_http_matches_a_decoded_http_layer(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "TCP", "HTTP"), protocol="HTTP")
        assert matches("HTTP", packet)

    def test_https_is_not_assumed_from_port_443(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "TCP"), protocol="TCP", dst_port=443)
        assert not matches("HTTPS", packet)

    def test_https_matches_a_decoded_tls_layer(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "TCP", "TLS"), protocol="TLSv1.3")
        assert matches("HTTPS", packet)

    def test_https_matches_a_tls_protocol_column_without_a_chain_entry(self) -> None:
        """A segment of a TLS record is handled by the TLS dissector; the
        chain does not list TLS because no complete record was decoded in that
        frame. Measured: relying on the chain alone missed 8 of 185 frames."""
        packet = _Packet(layers=("ETH", "IP", "TCP"), protocol="TLSv1.2")
        assert matches("HTTPS", packet)

    def test_dtls_is_not_tls(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "UDP", "DTLS"), protocol="DTLS")
        assert not matches("HTTPS", packet)

    def test_dns_is_not_limited_to_udp_53(self) -> None:
        """DNS over TCP is DNS."""
        packet = _Packet(layers=("ETH", "IP", "TCP", "DNS"), protocol="DNS",
                         dst_port=53)
        assert matches("DNS", packet)
        assert matches("TCP", packet)

    def test_udp_53_without_a_dns_layer_is_not_dns(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "UDP"), protocol="UDP", dst_port=53)
        assert not matches("DNS", packet)

    def test_icmp_covers_both_families(self) -> None:
        assert matches("ICMP", _Packet(layers=("ETH", "IP", "ICMP"), protocol="ICMP"))
        assert matches("ICMP",
                       _Packet(layers=("ETH", "IPV6", "ICMPV6"), protocol="ICMPv6"))

    def test_arp_matches_without_any_ip_layer(self) -> None:
        """ARP frames carry no IP fields at all; the filter must not need them."""
        packet = _Packet(layers=("ETH", "ARP"), protocol="ARP")
        assert matches("ARP", packet)
        assert not matches("TCP", packet)

    def test_the_web_view_was_removed(self) -> None:
        """It was exactly HTTP or HTTPS/TLS, which both remain on the bar."""
        from aethra_sec.ui.screens.traffic import PROTOCOL_BUTTONS

        assert "WEB" not in PROTOCOL_BY_KEY
        assert "WEB" not in {key for key, _label in PROTOCOL_BUTTONS}


# ---------------------------------------------------------------------------
# Sites: names actually looked up or connected to
# ---------------------------------------------------------------------------
class TestSites:
    def test_a_tls_server_name_is_a_site(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "TCP", "TLS"), protocol="TLSv1.3",
                         tls_sni="www.wikipedia.org")
        assert matches("SITES", packet)

    def test_an_http_host_is_a_site(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "TCP", "HTTP"), protocol="HTTP",
                         http_host="neverssl.com")
        assert matches("SITES", packet)

    def test_a_dns_question_is_a_site(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "UDP", "DNS"), protocol="DNS",
                         dns_query="example.com", dns_response=False)
        assert matches("SITES", packet)

    def test_a_dns_answer_is_not_counted_again(self) -> None:
        """A response repeats the question; counting it would double every lookup."""
        packet = _Packet(layers=("ETH", "IP", "UDP", "DNS"), protocol="DNS",
                         dns_query="example.com", dns_response=True)
        assert not matches("SITES", packet)

    def test_a_reverse_lookup_is_not_a_site(self) -> None:
        packet = _Packet(layers=("ETH", "IP", "UDP", "DNS"), protocol="DNS",
                         dns_query="31.100.168.192.in-addr.arpa", dns_response=False)
        assert not matches("SITES", packet)

    def test_ssdp_multicast_discovery_is_not_a_site(self) -> None:
        """The real finding behind this file.

        SSDP reuses HTTP header syntax, so TShark's own ``http.host`` field is
        populated by the SSDP dissector with the multicast discovery address
        239.255.255.250:1900. Cross-checked on live traffic, TShark's filter
        matched 4 such frames that this application does not - because
        ``http.host`` here is scoped to the HTTP layer. A multicast discovery
        address is not a site, so the application is right and TShark's raw
        count is the thing not to copy.
        """
        packet = _Packet(
            layers=("ETH", "ETHERTYPE", "IP", "UDP", "SSDP"), protocol="SSDP",
            http_host="239.255.255.250:1900",
        )
        assert not matches("SITES", packet)
        assert not matches("HTTP", packet)


# ---------------------------------------------------------------------------
# Direction is an independent axis
# ---------------------------------------------------------------------------
class TestDirectionAxis:
    @pytest.mark.parametrize(
        "key,value",
        [("INCOMING", "incoming"), ("OUTGOING", "outgoing"), ("TRANSIT", "transit")],
    )
    def test_each_direction_view_matches_only_its_own(self, key, value) -> None:  # noqa: ANN001
        from aethra_sec.analytics.display_filter import DIRECTION_BY_KEY

        compiled = compile_filter(DIRECTION_BY_KEY[key].expression)
        assert compiled.matches(_Packet(direction=value))
        for other in ("incoming", "outgoing", "transit", "broadcast"):
            if other != value:
                assert not compiled.matches(_Packet(direction=other))

    def test_direction_and_protocol_combine(self) -> None:
        """The bar has two axes, so Incoming + TCP is a real combination."""
        composed = compose_filter(FilterRequest(direction="INCOMING", protocol="TCP"))
        incoming_tcp = _Packet(layers=("ETH", "IP", "TCP"), protocol="TCP",
                               direction="incoming")
        outgoing_tcp = _Packet(layers=("ETH", "IP", "TCP"), protocol="TCP",
                               direction="outgoing")
        incoming_udp = _Packet(layers=("ETH", "IP", "UDP"), protocol="UDP",
                               direction="incoming")
        assert composed.compiled.matches(incoming_tcp)
        assert not composed.compiled.matches(outgoing_tcp)
        assert not composed.compiled.matches(incoming_udp)

    def test_all_traffic_is_the_absence_of_a_filter(self) -> None:
        composed = compose_filter(FilterRequest())
        assert composed.compiled.matches_everything


# ---------------------------------------------------------------------------
# Selecting a view replaces the previous one
# ---------------------------------------------------------------------------
class TestNoStackingOrStaleState:
    TRANSITIONS = [
        ("TCP", "UDP"), ("HTTP", "ARP"), ("SITES", "HTTPS"), ("DNS", "ICMP"),
    ]

    @pytest.mark.parametrize("before,after", TRANSITIONS)
    def test_a_new_protocol_replaces_the_old(self, before, after) -> None:  # noqa: ANN001
        composed = compose_filter(FilterRequest(protocol=after))
        assert PROTOCOL_BY_KEY[after].expression in composed.expression
        assert PROTOCOL_BY_KEY[before].expression not in composed.expression

    def test_clearing_the_protocol_leaves_the_direction(self) -> None:
        composed = compose_filter(FilterRequest(direction="INCOMING", protocol=""))
        assert "direction" in composed.expression
        for preset in PROTOCOL_BY_KEY.values():
            assert preset.expression not in composed.expression

    def test_clearing_everything_matches_everything(self) -> None:
        assert compose_filter(FilterRequest()).compiled.matches_everything


# ---------------------------------------------------------------------------
# A display filter is not a capture filter
# ---------------------------------------------------------------------------
class TestItOnlyFiltersTheDisplay:
    def test_applying_a_filter_never_touches_the_reader(self) -> None:
        from aethra_sec.services.packet_capture import PacketCaptureService

        body = inspect.getsource(PacketCaptureService.set_display_filter)
        for forbidden in ("self._reader", "start(", "stop(", "Popen", "terminate"):
            assert forbidden not in body, (
                "changing a display filter must not restart capture: a user "
                "clicking through the filter bar would lose packets"
            )
        assert "self.view.apply_filter" in body

    def test_a_filter_change_re_evaluates_what_is_already_held(self) -> None:
        """Retained packets survive a filter change.

        The view swaps the predicate and asks for a rescan rather than
        discarding what it holds, so switching from TCP to UDP shows the UDP
        packets already captured instead of only those arriving afterwards.
        """
        from aethra_sec.services.packet_view import PacketView

        body = inspect.getsource(PacketView.apply_filter)
        assert "self._rescan_requested = True" in body
        assert "self._generation += 1" in body, (
            "a new generation is what lets the screen discard rows filtered "
            "under the previous predicate"
        )
        for forbidden in ("_retained.clear()", "_ingest.clear()"):
            assert forbidden not in body, (
                "a display filter must not throw away captured packets"
            )


# ---------------------------------------------------------------------------
# Odd packets must not raise
# ---------------------------------------------------------------------------
class TestMalformedInput:
    @pytest.mark.parametrize("key", list(PROTOCOL_BY_KEY))
    def test_every_preset_survives_an_empty_packet(self, key: str) -> None:
        assert matches(key, _Packet()) in (True, False)

    @pytest.mark.parametrize("key", list(PROTOCOL_BY_KEY))
    def test_every_preset_survives_an_object_with_nothing_on_it(self, key: str) -> None:
        class Bare:
            pass

        compiled = compile_filter(PROTOCOL_BY_KEY[key].expression)
        assert compiled.matches(Bare()) in (True, False)

    def test_a_packet_with_no_ip_layer_does_not_raise(self) -> None:
        packet = _Packet(layers=("ETH", "ARP"), protocol="ARP",
                         src_ip="", dst_ip="", src_port=None, dst_port=None)
        for key in PROTOCOL_BY_KEY:
            assert matches(key, packet) in (True, False)

    def test_an_exception_inside_a_predicate_is_not_a_match(self) -> None:
        class Hostile:
            @property
            def layers(self):  # noqa: ANN202
                raise RuntimeError("bad packet")

        assert compile_filter("tcp").matches(Hostile()) is False


# ---------------------------------------------------------------------------
# Statistics and the filter agree about a packet
# ---------------------------------------------------------------------------
class TestCountersAndFilterAgree:
    def test_protocol_present_is_the_one_shared_judgement(self) -> None:
        """The counts beside the table and the filter must use one answer, or
        a view can show more rows than its own chart admits exist."""
        body = inspect.getsource(protocol_present)
        assert "tls_present" in body
        packet = _Packet(layers=("ETH", "IP", "TCP"), protocol="TLSv1.2")
        assert protocol_present(packet, "tls") is matches("HTTPS", packet)

    def test_the_bar_offers_exactly_the_documented_views(self) -> None:
        from aethra_sec.ui.screens.traffic import (
            DIRECTION_BUTTONS,
            PROTOCOL_BUTTONS,
        )

        assert [key for key, _ in DIRECTION_BUTTONS] == [
            "", "INCOMING", "OUTGOING", "TRANSIT",
        ]
        assert [key for key, _ in PROTOCOL_BUTTONS] == [
            "HTTP", "HTTPS", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP",
        ]

    def test_every_bar_view_resolves_to_a_preset(self) -> None:
        from aethra_sec.ui.screens.traffic import PROTOCOL_BUTTONS

        for key, _label in PROTOCOL_BUTTONS:
            assert key in PROTOCOL_BY_KEY, f"{key} has no preset behind it"
