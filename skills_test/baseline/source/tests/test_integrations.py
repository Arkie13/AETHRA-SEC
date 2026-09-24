"""Parser tests for the three tool integrations.

Nmap output, PyShark packet objects and Snort alerts all arrive from outside the
application, so the parsers must extract what is there, tolerate what is not,
and never invent a value.
"""

from __future__ import annotations

import socket
import struct

import pytest

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.integrations.nmap.parser import (
    FindingBuilder,
    VulnKnowledgeEntry,
    extract_script_references,
    parse_scan_result,
)
from aethra_sec.integrations.pyshark_capture.mapper import map_packet
from aethra_sec.integrations.snort.alertpkt import build_alertpkt, decode_alertpkt
from aethra_sec.integrations.snort.parser import (
    parse_alert_line,
    parse_csv,
    parse_fast,
    parse_json,
    parse_syslog,
)
from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel
from tests.conftest import make_frame


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
#: A python-nmap result structure with the shape Nmap actually produces.
NMAP_RESULT = {
    "nmap": {"command_line": "nmap -sT -sV 192.168.1.25", "scanstats": {}},
    "scan": {
        "192.168.1.25": {
            "hostnames": [{"name": "server.lab.local", "type": "PTR"}],
            "addresses": {"ipv4": "192.168.1.25", "mac": "00:11:22:33:44:55"},
            "vendor": {"00:11:22:33:44:55": "Dell Inc."},
            "status": {"state": "up", "reason": "syn-ack"},
            "osmatch": [
                {
                    "name": "Linux 5.4 - 5.10",
                    "accuracy": "96",
                    "osclass": [{"osfamily": "Linux", "vendor": "Linux"}],
                }
            ],
            "tcp": {
                22: {
                    "state": "open", "reason": "syn-ack", "name": "ssh",
                    "product": "OpenSSH", "version": "8.9p1",
                    "extrainfo": "Ubuntu Linux", "cpe": "cpe:/a:openbsd:openssh:8.9p1",
                    "script": {"vulners": "  CVE-2023-38408  7.8  https://vulners.com"},
                },
                80: {
                    "state": "open", "reason": "syn-ack", "name": "http",
                    "product": "nginx", "version": "1.18.0", "extrainfo": "",
                    "cpe": "",
                },
                23: {
                    "state": "open", "reason": "syn-ack", "name": "telnet",
                    "product": "", "version": "", "extrainfo": "", "cpe": "",
                },
                3306: {
                    "state": "closed", "reason": "conn-refused", "name": "mysql",
                    "product": "", "version": "", "extrainfo": "", "cpe": "",
                },
            },
        },
        "192.168.1.99": {
            "hostnames": [],
            "addresses": {"ipv4": "192.168.1.99"},
            "status": {"state": "down", "reason": "no-response"},
            "tcp": {},
        },
    },
}


class TestNmapParsing:
    """Nmap output becomes observations, and observations become findings."""

    def test_parses_hosts_and_ports(self) -> None:
        """Hosts, addresses, OS and ports are read from the real structure."""
        hosts = parse_scan_result(NMAP_RESULT)
        assert len(hosts) == 2
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        assert server.hostname == "server.lab.local"
        assert server.mac_address == "00:11:22:33:44:55"
        assert server.vendor == "Dell Inc."
        assert server.status is HostStatus.UP
        assert server.os_name == "Linux 5.4 - 5.10"
        assert server.os_accuracy == 96
        assert server.os_family == "Linux"
        assert len(server.ports) == 4
        assert len(server.open_ports) == 3

    def test_down_host_has_no_invented_data(self) -> None:
        """A host that did not respond carries no fabricated detail."""
        hosts = parse_scan_result(NMAP_RESULT)
        down = next(h for h in hosts if h.ip_address == "192.168.1.99")
        assert down.status is HostStatus.DOWN
        assert down.hostname == ""
        assert down.os_name == ""
        assert down.ports == []

    def test_empty_result_yields_nothing(self) -> None:
        """An empty scan produces no hosts, not a placeholder."""
        assert parse_scan_result({}) == []
        assert parse_scan_result({"scan": {}}) == []

    def test_findings_only_for_open_ports(self) -> None:
        """Closed ports produce no finding."""
        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine()).build_for_host(server)
        ports = {f.port for f in findings if f.port}
        assert 3306 not in ports
        assert {22, 80, 23} <= ports

    def test_finding_separates_observation_from_concern(self) -> None:
        """A finding states what was seen and why it may matter (§19)."""
        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine()).build_for_host(server)
        ssh = next(f for f in findings if f.port == 22)
        assert "OPEN" in ssh.observation
        assert "not automatically a vulnerability" in ssh.concern
        assert ssh.risk_rationale.startswith("Risk ")
        assert ssh.source is EvidenceSource.NMAP

    def test_no_cve_is_invented_without_a_source(self) -> None:
        """Without a configured source, the finding says so plainly."""
        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine()).build_for_host(server)
        http = next(f for f in findings if f.port == 80)
        assert http.reference == ""
        assert http.verification_required is True
        assert "further vulnerability verification required" in http.reference_text

    def test_nse_identifiers_are_used_when_nmap_printed_them(self) -> None:
        """A real NSE identifier is cited rather than ignored."""
        entry = NMAP_RESULT["scan"]["192.168.1.25"]
        references = extract_script_references(entry)
        assert references[22] == ["CVE-2023-38408"]

        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine()).build_for_host(
            server, script_references=references
        )
        ssh = next(f for f in findings if f.port == 22)
        assert "CVE-2023-38408" in ssh.reference
        assert ssh.verification_required is False

    def test_configured_knowledge_base_is_applied(self) -> None:
        """An administrator knowledge-base entry overrides the generic text."""
        knowledge = (
            VulnKnowledgeEntry(
                service="http", product_pattern="nginx", version_pattern=r"1\.18",
                port=None, title="nginx 1.18 requires review",
                concern="This build is superseded.", risk_level=RiskLevel.HIGH,
                reference="LAB-2024-001", reference_source="Lab knowledge base",
            ),
        )
        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine(), knowledge).build_for_host(server)
        http = next(f for f in findings if f.port == 80)
        assert http.title == "nginx 1.18 requires review"
        assert http.reference == "LAB-2024-001"
        assert http.risk_level is RiskLevel.HIGH
        assert http.verification_required is False

    def test_cleartext_summary_finding(self) -> None:
        """Several unencrypted services on one host raise a summary finding."""
        hosts = parse_scan_result(NMAP_RESULT)
        server = next(h for h in hosts if h.ip_address == "192.168.1.25")
        findings = FindingBuilder(RiskEngine()).build_for_host(server)
        summary = [f for f in findings if "unencrypted" in f.title.lower()]
        assert summary, "telnet + http should raise a cleartext summary"
        assert summary[0].port is None

    def test_malformed_host_entry_is_skipped(self) -> None:
        """One unusable host entry does not discard the whole scan."""
        broken = {"scan": {"192.168.1.5": "not-a-dict", "192.168.1.6": {
            "addresses": {"ipv4": "192.168.1.6"}, "status": {"state": "up"}, "tcp": {},
        }}}
        hosts = parse_scan_result(broken)
        assert [h.ip_address for h in hosts] == ["192.168.1.6"]


# ---------------------------------------------------------------------------
# PyShark
# ---------------------------------------------------------------------------
class _FakeLayer:
    """A stand-in for a PyShark layer, including its raising behaviour."""

    def __init__(self, name: str, **fields: object) -> None:
        self.layer_name = name
        self._fields = fields

    def __getattr__(self, item: str) -> object:
        if item in self._fields:
            return self._fields[item]
        raise AttributeError(item)  # PyShark raises for unknown fields

    @property
    def field_names(self) -> list[str]:
        """Field names, as PyShark exposes them."""
        return list(self._fields)

    def get_field_value(self, name: str) -> object:
        """Field lookup used by the detail panel."""
        return self._fields.get(name)


class _FakePacket:
    """A stand-in for a PyShark packet."""

    def __init__(self, layers: list[_FakeLayer], **attributes: object) -> None:
        self.layers = layers
        self._index = {layer.layer_name.upper(): layer for layer in layers}
        for key, value in attributes.items():
            setattr(self, key, value)

    def __contains__(self, item: str) -> bool:
        return item.upper() in self._index

    def __getitem__(self, item: str) -> _FakeLayer:
        return self._index[item.upper()]


class TestPacketMapping:
    """Real packets are irregular; the mapper must never invent a field."""

    def test_maps_a_tcp_packet(self) -> None:
        """A full TCP packet yields every field it actually carries."""
        packet = _FakePacket(
            [
                _FakeLayer("eth", src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb"),
                _FakeLayer("ip", src="192.168.1.50", dst="192.168.1.25", ttl="64"),
                _FakeLayer("tcp", srcport="44321", dstport="22", flags="0x0002"),
            ],
            sniff_timestamp="1700000000.5",
            highest_layer="TCP",
            transport_layer="TCP",
            length="74",
            number="42",
        )
        mapped = map_packet(packet, "eth0")
        assert mapped is not None
        assert mapped.src_ip == "192.168.1.50"
        assert mapped.dst_ip == "192.168.1.25"
        assert mapped.src_port == 44321
        assert mapped.dst_port == 22
        assert mapped.protocol == "TCP"
        assert mapped.ttl == 64
        assert mapped.tcp_flags == 2
        assert mapped.is_syn_only
        assert mapped.length == 74
        assert mapped.interface == "eth0"
        assert mapped.number == 42

    def test_arp_packet_has_no_ports(self) -> None:
        """An ARP frame yields no ports and no TCP flags."""
        packet = _FakePacket(
            [
                _FakeLayer("eth", src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff"),
                _FakeLayer(
                    "arp", src_proto_ipv4="192.168.1.50",
                    dst_proto_ipv4="192.168.1.1", src_hw_mac="00:11:22:33:44:55",
                ),
            ],
            sniff_timestamp="1700000001.0", highest_layer="ARP",
            transport_layer=None, length="42",
        )
        mapped = map_packet(packet)
        assert mapped is not None
        assert mapped.protocol == "ARP"
        assert mapped.src_port is None
        assert mapped.dst_port is None
        assert mapped.tcp_flags is None
        assert mapped.flags_text == "-"

    def test_icmp_packet(self) -> None:
        """ICMP is recognised and carries no transport ports."""
        packet = _FakePacket(
            [
                _FakeLayer("eth", src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb"),
                _FakeLayer("ip", src="10.0.0.1", dst="10.0.0.2", ttl="128"),
                _FakeLayer("icmp", type="8", code="0"),
            ],
            sniff_timestamp="1700000002.0", highest_layer="ICMP",
            transport_layer=None, length="98",
        )
        mapped = map_packet(packet)
        assert mapped is not None
        assert mapped.protocol == "ICMP"
        assert mapped.ttl == 128
        assert mapped.src_port is None

    def test_application_protocol_from_layers(self) -> None:
        """A decoded application layer is reported as such."""
        packet = _FakePacket(
            [
                _FakeLayer("eth", src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb"),
                _FakeLayer("ip", src="192.168.1.50", dst="192.168.1.25", ttl="64"),
                _FakeLayer("tcp", srcport="50000", dstport="80", flags="0x0018"),
                _FakeLayer("http", request_method="GET"),
            ],
            sniff_timestamp="1700000003.0", highest_layer="HTTP",
            transport_layer="TCP", length="512",
        )
        mapped = map_packet(packet)
        assert mapped is not None
        assert mapped.app_protocol == "HTTP"

    def test_missing_fields_never_raise(self) -> None:
        """A packet stripped of almost everything still maps or is skipped."""
        packet = _FakePacket([_FakeLayer("data")], sniff_timestamp="1700000004.0")
        mapped = map_packet(packet)
        assert mapped is not None
        assert mapped.src_ip == ""
        assert mapped.length == 0

    def test_unreadable_object_is_reported_as_a_decode_error(self) -> None:
        """An object that cannot be read at all yields ``None``."""
        assert map_packet(object()) is None


# ---------------------------------------------------------------------------
# Snort
# ---------------------------------------------------------------------------
FAST_LINE = (
    "01/15-14:22:31.123456  [**] [1:2001219:19] ET SCAN Potential SSH Scan "
    "[**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} "
    "192.168.1.50:44321 -> 192.168.1.25:22"
)
SYSLOG_LINE = (
    "<33>Jan 15 14:22:31 sensor01 snort[2451]: [1:2001219:19] ET SCAN "
    "Potential SSH Scan [Classification: Attempted Information Leak] "
    "[Priority: 2]: {TCP} 192.168.1.50:44321 -> 192.168.1.25:22"
)
JSON_LINE = (
    '{"timestamp":1705328551.5,"gid":1,"sid":2001219,"rev":19,'
    '"msg":"ET SCAN Potential SSH Scan","class":"Attempted Information Leak",'
    '"priority":2,"proto":"TCP","src_addr":"192.168.1.50","src_port":44321,'
    '"dst_addr":"192.168.1.25","dst_port":22,"iface":"eth0"}'
)
CSV_LINE = (
    "01/15-14:22:31.123456 ,1,2001219,19,ET SCAN Potential SSH Scan,TCP,"
    "192.168.1.50,44321,192.168.1.25,22,00:11:22:33:44:55,66:77:88:99:AA:BB,"
    "74,******S*,0,0,0,64240,64,0,12345,60,20"
)


class TestSnortTextParsers:
    """Every documented alert format is parsed to the same model."""

    @pytest.mark.parametrize(
        ("line", "expected_format"),
        [
            (FAST_LINE, "alert_fast"),
            (SYSLOG_LINE, "alert_syslog"),
            (JSON_LINE, "alert_json"),
            (CSV_LINE, "alert_csv"),
        ],
    )
    def test_formats_are_detected_and_parsed(self, line: str, expected_format: str) -> None:
        """Auto-detection picks the right parser and extracts the same facts."""
        alert = parse_alert_line(line)
        assert alert is not None
        assert alert.format == expected_format
        assert alert.generator_id == 1
        assert alert.signature_id == 2001219
        assert alert.revision == 19
        assert alert.message == "ET SCAN Potential SSH Scan"
        assert alert.src_ip == "192.168.1.50"
        assert alert.src_port == 44321
        assert alert.dst_ip == "192.168.1.25"
        assert alert.dst_port == 22
        assert alert.protocol == "TCP"
        assert alert.raw == line

    def test_alert_without_ports(self) -> None:
        """An ICMP alert has addresses but no ports."""
        alert = parse_fast(
            "03/02-09:11:02.000001  [**] [1:384:5] ICMP PING [**] "
            "[Classification: Misc activity] [Priority: 3] {ICMP} "
            "10.0.0.5 -> 10.0.0.9"
        )
        assert alert is not None
        assert alert.src_ip == "10.0.0.5"
        assert alert.src_port is None
        assert alert.dst_port is None

    def test_missing_priority_stays_none(self) -> None:
        """A field the sensor did not supply is not invented."""
        alert = parse_fast(
            "01/15-14:22:31.123456  [**] [1:1000:1] Test rule [**] {TCP} "
            "10.0.0.1:1 -> 10.0.0.2:2"
        )
        assert alert is not None
        assert alert.priority is None
        assert alert.classification == ""

    @pytest.mark.parametrize(
        "line",
        ["", "   ", "Running in IDS mode", "Commencing packet processing", "#comment"],
    )
    def test_non_alert_output_is_refused(self, line: str) -> None:
        """Ordinary Snort console output is not mistaken for an alert."""
        assert parse_alert_line(line) is None

    def test_json_keeps_unknown_fields_as_evidence(self) -> None:
        """Extra Snort 3 fields are retained rather than discarded."""
        alert = parse_json(JSON_LINE.replace("}", ',"pkt_num":12345}'))
        assert alert is not None
        assert alert.extra.get("pkt_num") == 12345

    def test_csv_requires_recognisable_content(self) -> None:
        """A random comma-separated line is not treated as an alert."""
        assert parse_csv("a,b,c") is None


class TestAlertPktDecoder:
    """The Alert Socket IPC binary format (§21)."""

    @pytest.mark.parametrize("sixty_four_bit", [True, False])
    def test_round_trip(self, sixty_four_bit: bool) -> None:
        """Both timeval widths decode to the same facts."""
        payload = build_alertpkt(
            "ET SCAN Potential SSH Scan",
            generator_id=1, signature_id=2001219, revision=19,
            classification=3, priority=2, event_id=7,
            timestamp=1705328551.123456,
            packet=make_frame("192.168.1.50", "192.168.1.25", 44321, 22),
            snaplen=1514, sixty_four_bit=sixty_four_bit,
        )
        decoded = decode_alertpkt(payload)
        assert decoded is not None
        assert decoded.message == "ET SCAN Potential SSH Scan"
        assert decoded.generator_id == 1
        assert decoded.signature_id == 2001219
        assert decoded.revision == 19
        assert decoded.priority == 2
        assert decoded.event_id == 7
        assert decoded.src_ip == "192.168.1.50"
        assert decoded.dst_ip == "192.168.1.25"
        assert decoded.src_port == 44321
        assert decoded.dst_port == 22
        assert decoded.protocol == "TCP"
        assert decoded.ttl == 64
        assert decoded.packet_decoded is True
        assert decoded.warnings == ()

    @pytest.mark.parametrize("snaplen", [1514, 8192, 65535])
    def test_decoder_is_independent_of_snap_length(self, snaplen: int) -> None:
        """Anchoring on the trailing Event makes SNAPLEN irrelevant."""
        payload = build_alertpkt(
            "Signature", signature_id=1234, priority=1,
            packet=make_frame("10.0.0.1", "10.0.0.2", 1000, 2000),
            snaplen=snaplen,
        )
        decoded = decode_alertpkt(payload)
        assert decoded is not None
        assert decoded.signature_id == 1234
        assert decoded.src_ip == "10.0.0.1"
        assert decoded.dst_port == 2000

    def test_udp_endpoints(self) -> None:
        """A UDP datagram yields UDP endpoints."""
        ethernet = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
        ip_header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0,
            socket.inet_aton("10.0.0.5"), socket.inet_aton("10.0.0.9"),
        )
        udp_header = struct.pack("!HHHH", 53, 40000, 8, 0)
        payload = build_alertpkt(
            "DNS alert", packet=ethernet + ip_header + udp_header, snaplen=1514
        )
        decoded = decode_alertpkt(payload)
        assert decoded is not None
        assert decoded.protocol == "UDP"
        assert decoded.src_port == 53
        assert decoded.dst_port == 40000

    def test_alert_without_a_packet_still_decodes(self) -> None:
        """An alert with no attached packet decodes and says endpoints are absent."""
        payload = build_alertpkt("No packet attached", packet=b"", snaplen=64)
        decoded = decode_alertpkt(payload)
        assert decoded is not None
        assert decoded.message == "No packet attached"
        assert decoded.src_ip == ""
        assert "embedded packet did not yield IPv4 endpoints" in decoded.warnings

    @pytest.mark.parametrize(
        "payload", [b"", b"\x01\x02\x03", b"\x00" * 100, b"\xff" * 300]
    )
    def test_garbage_is_refused(self, payload: bytes) -> None:
        """Non-Alertpkt data is refused rather than half-decoded."""
        assert decode_alertpkt(payload) is None
