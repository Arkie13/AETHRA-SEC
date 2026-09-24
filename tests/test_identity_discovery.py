"""Hostname and operating system discovery for a scanned host.

A scan of 192.168.1.14 returned its IP, its status, its MAC address and its
open ports, and left Hostname and Operating system empty. Neither omission was
a parser bug. Both were the scan never asking the question:

* the default ``standard`` profile is ``-sT -sV --top-ports 1000``. There is no
  ``-O`` in it, so Nmap emits no ``osmatch`` element at all - there was nothing
  for the parser to find;
* Nmap's own reverse lookup returned ``[{'name': '', 'type': ''}]``. The device
  has no PTR record, which is the normal state for a machine on a LAN whose
  router hands out addresses and registers no names.

The fix asks both questions properly, with Nmap's own discovery scripts and
the local resolver. What is pinned here:

* every parser reads a real script's real output format, including the
  ``\\x00`` padding ``nbstat`` emits and the ``<unknown>`` placeholders both
  scripts use for a field they could not fill;
* sources are preferred in order of how much they can be trusted, and a
  weaker source never overwrites a stronger one;
* the probe's arguments are constants, and its target is re-validated - an
  address carrying shell metacharacters is refused, not quoted;
* ``-O`` is left off when the process cannot use raw sockets, rather than
  being passed and failing;
* a host that answers nothing reports ``Unknown`` with a note saying why, and
  never a fabricated name or OS;
* the fields survive the trip through the model to the screen.
"""

from __future__ import annotations

import pytest

from aethra_sec.integrations.nmap.identity import (
    IDENTITY_PORTS,
    IDENTITY_SCRIPTS,
    HostIdentity,
    _encode_question,
    _first_ptr_answer,
    identity_arguments,
    identity_from_scan,
    identity_request,
    mdns_hostname,
    parse_nbstat,
    parse_os_match,
    parse_ptr_name,
    parse_smb_os_discovery,
    validated_target,
)
from aethra_sec.models.enums import HostStatus
from aethra_sec.models.scan import NOT_DETECTED, ScanHostResult
from aethra_sec.utils.validation import ValidationError

# ---------------------------------------------------------------------------
# Real script output, copied verbatim from Nmap runs
# ---------------------------------------------------------------------------
SMB_OUTPUT = """
  OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)
  OS CPE: cpe:/o:microsoft:windows_10::-
  Computer name: LAPTOP-ABC123
  NetBIOS computer name: LAPTOP-ABC123\\x00
  Domain name: WORKGROUP
  Forest name: \\x00
  FQDN: LAPTOP-ABC123
  System time: 2026-08-22T10:14:33+08:00
"""

NBSTAT_OUTPUT = (
    "NetBIOS name: LAPTOP-ABC123, NetBIOS user: <unknown>, "
    "NetBIOS MAC: 3c:52:82:1a:0b:7e (Intel Corporate)"
)

# A host that answered the SMB port but volunteered nothing useful.
SMB_EMPTY_OUTPUT = """
  OS: <unknown>
  Computer name: <unknown>
  NetBIOS computer name:
"""


def _host_entry(**parts: object) -> dict[str, object]:
    """One python-nmap host entry with the given scripts and matches."""
    entry: dict[str, object] = {"hostnames": [{"name": "", "type": ""}]}
    scripts = []
    if "smb" in parts:
        scripts.append({"id": "smb-os-discovery", "output": parts["smb"]})
    if "nbstat" in parts:
        scripts.append({"id": "nbstat", "output": parts["nbstat"]})
    if scripts:
        entry["hostscript"] = scripts
    if "ptr" in parts:
        entry["hostnames"] = [{"name": parts["ptr"], "type": "PTR"}]
    if "osmatch" in parts:
        entry["osmatch"] = parts["osmatch"]
    return entry


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def test_smb_output_yields_name_os_and_cpe() -> None:
    """The most trustworthy source: the host describing itself."""
    found = parse_smb_os_discovery(SMB_OUTPUT)
    assert found["hostname"] == "LAPTOP-ABC123"
    assert found["os"] == "Windows 10 Pro 19041 (Windows 10 Pro 6.3)"
    assert found["cpe"] == "cpe:/o:microsoft:windows_10::-"
    assert found["domain"] == "WORKGROUP"


def test_smb_placeholders_are_not_mistaken_for_answers() -> None:
    """``<unknown>`` is the script saying it has nothing, not a value."""
    assert parse_smb_os_discovery(SMB_EMPTY_OUTPUT) == {}


def test_nbstat_name_is_read_and_stripped() -> None:
    """NetBIOS names arrive padded; the padding is not part of the name."""
    assert parse_nbstat(NBSTAT_OUTPUT) == "LAPTOP-ABC123"
    assert parse_nbstat("NetBIOS name: <unknown>, NetBIOS user: <unknown>") == ""
    assert parse_nbstat("") == ""


def test_os_match_keeps_the_accuracy_with_the_answer() -> None:
    """A fingerprint is an inference, so its confidence travels with it."""
    found = parse_os_match(
        _host_entry(
            osmatch=[
                {
                    "name": "Microsoft Windows 10 1909 - 21H1",
                    "accuracy": "95",
                    "osclass": [
                        {
                            "osfamily": "Windows",
                            "osgen": "10",
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                        }
                    ],
                },
                {"name": "Microsoft Windows Server 2019", "accuracy": "88"},
            ]
        )
    )
    assert found["name"] == "Microsoft Windows 10 1909 - 21H1"
    assert found["accuracy"] == 95
    assert found["family"] == "Windows"
    assert found["cpe"] == "cpe:/o:microsoft:windows_10"


def test_empty_ptr_entry_is_not_a_hostname() -> None:
    """The exact shape a nameless LAN address produces must yield nothing."""
    assert parse_ptr_name({"hostnames": [{"name": "", "type": ""}]}) == ""
    assert parse_ptr_name({}) == ""


# ---------------------------------------------------------------------------
# Source precedence
# ---------------------------------------------------------------------------
def test_ptr_record_outranks_smb_and_netbios_for_a_name() -> None:
    """DNS is authoritative for a name, so it wins when it has one."""
    identity = identity_from_scan(
        _host_entry(ptr="server.lab.local", smb=SMB_OUTPUT, nbstat=NBSTAT_OUTPUT)
    )
    assert identity.hostname == "server.lab.local"
    assert identity.hostname_source == "reverse DNS"


def test_smb_names_the_host_when_dns_does_not() -> None:
    """The case that was failing: no PTR record, but the host knows itself."""
    identity = identity_from_scan(_host_entry(smb=SMB_OUTPUT, nbstat=NBSTAT_OUTPUT))
    assert identity.hostname == "LAPTOP-ABC123"
    assert identity.hostname_source == "SMB"


def test_netbios_names_the_host_when_smb_is_silent() -> None:
    """A machine with SMB shut off still answers a NetBIOS name query."""
    identity = identity_from_scan(_host_entry(nbstat=NBSTAT_OUTPUT))
    assert identity.hostname == "LAPTOP-ABC123"
    assert identity.hostname_source == "NetBIOS"


def test_reported_os_outranks_a_guessed_one() -> None:
    """What a host says about itself beats what its packet timings suggest."""
    identity = identity_from_scan(
        _host_entry(
            smb=SMB_OUTPUT,
            osmatch=[{"name": "Linux 4.15 - 5.8", "accuracy": "89"}],
        )
    )
    assert identity.os_name.startswith("Windows 10 Pro")
    assert identity.os_source == "SMB"
    assert identity.os_cpe == "cpe:/o:microsoft:windows_10::-"
    assert identity.os_family == "Windows"
    assert identity.os_version == "10"


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        # The trap: the parenthesised 6.3 is the SMB dialect's NT version.
        # Reading it as the release records Windows 10 as Windows 8.1.
        ("Windows 10 Pro 19041 (Windows 10 Pro 6.3)", "10"),
        ("Windows Server 2019 Standard 17763 (Windows Server 2019 6.3)", "2019"),
        ("Windows 7 Professional 7601 Service Pack 1", "7"),
        ("Unix (Samba 4.13.13-Debian)", "4.13.13"),
    ],
)
def test_version_is_the_release_not_the_smb_dialect(
    reported: str, expected: str
) -> None:
    """A version that maps to the wrong CVE set is worse than no version."""
    identity = identity_from_scan(
        _host_entry(smb=f"  OS: {reported}\n  Computer name: BOX\n")
    )
    assert identity.os_version == expected


def test_fingerprint_is_used_when_the_host_says_nothing() -> None:
    """Without SMB, Nmap's inference is the only answer available."""
    identity = identity_from_scan(
        _host_entry(
            osmatch=[
                {
                    "name": "Microsoft Windows 10 1909 - 21H1",
                    "accuracy": "95",
                    "osclass": [{"osfamily": "Windows", "osgen": "10"}],
                }
            ]
        )
    )
    assert identity.os_source == "Nmap fingerprint"
    assert identity.os_accuracy == 95


# ---------------------------------------------------------------------------
# Nothing is invented when nothing is found
# ---------------------------------------------------------------------------
def test_a_silent_host_yields_no_answer_and_an_explanation() -> None:
    """The honest outcome: two empty fields and two reasons, no invention."""
    identity = identity_from_scan(_host_entry())
    assert identity.hostname == ""
    assert identity.os_name == ""
    assert not identity.found_hostname
    assert not identity.found_os
    assert len(identity.notes) == 2
    assert any("PTR record" in note for note in identity.notes)
    assert any("raw sockets" in note for note in identity.notes)


def test_unknown_is_shown_rather_than_a_dash() -> None:
    """The screen reads from the model, and the model never returns a dash."""
    host = ScanHostResult(ip_address="192.168.1.14", status=HostStatus.UP)
    assert host.hostname_text == NOT_DETECTED
    assert host.os_text == NOT_DETECTED

    host.os_family = "Windows"
    assert host.os_text == "Windows (family only)"

    host.os_name = "Microsoft Windows 10 1909 - 21H1"
    host.os_version = "10"
    host.os_accuracy = 95
    assert host.os_text == "Microsoft Windows 10 1909 - 21H1 (95%)"

    host.hostname = "LAPTOP-ABC123"
    assert host.hostname_text == "LAPTOP-ABC123"


def test_summary_names_its_sources() -> None:
    """A result is judged on where it came from, so the log says."""
    identity = HostIdentity(
        hostname="LAPTOP-ABC123",
        hostname_source="SMB",
        os_name="Windows 10 Pro",
        os_source="SMB",
    )
    line = identity.summary()
    assert "LAPTOP-ABC123" in line and "via SMB" in line


# ---------------------------------------------------------------------------
# The probe is bounded, constant, and validates its target
# ---------------------------------------------------------------------------
def test_arguments_are_constants_and_bounded() -> None:
    """Three ports, two safe scripts, one timeout. Nothing else is contacted."""
    unprivileged = identity_arguments(privileged=False)
    assert f"-p {IDENTITY_PORTS}" in unprivileged
    assert f"--script {IDENTITY_SCRIPTS}" in unprivileged
    assert "--host-timeout" in unprivileged
    assert "-O" not in unprivileged


def test_os_fingerprinting_is_only_attempted_when_it_can_work() -> None:
    """``-O`` needs raw sockets; passing it without them only wastes a scan."""
    assert "-O --osscan-guess" in identity_arguments(privileged=True)


def test_service_detection_runs_whether_or_not_we_are_privileged() -> None:
    """The banner is how an OS is identified when ``-O`` cannot run at all.

    ``Microsoft Windows RPC`` on port 135 settles the family on its own, and
    it costs nothing that ``-O`` was unavailable.
    """
    assert "-sV" in identity_arguments(privileged=False).split()
    assert "-sV" in identity_arguments(privileged=True).split()


def test_no_forbidden_script_category_is_ever_requested() -> None:
    """The probe reads what a service volunteers. It never authenticates."""
    for forbidden in ("brute", "exploit", "intrusive", "dos", "auth", "vuln"):
        assert forbidden not in IDENTITY_SCRIPTS


@pytest.mark.parametrize(
    "hostile",
    [
        "192.168.1.14; rm -rf /",
        "192.168.1.14 && shutdown",
        "192.168.1.14 -oN /etc/passwd",
        "$(whoami)",
        "192.168.1.0/24",
        "",
    ],
)
def test_a_target_that_is_not_a_single_address_is_refused(hostile: str) -> None:
    """The probe builds a command line, so its target is re-validated here."""
    with pytest.raises(ValidationError):
        validated_target(hostile)
    with pytest.raises(ValidationError):
        identity_request(hostile, privileged=False)


def test_request_carries_only_validated_parts() -> None:
    """Everything in the request originates from the module, not the caller."""
    request = identity_request("192.168.1.14", privileged=False)
    assert request.target == "192.168.1.14"
    assert request.profile.key == "identity"
    assert request.argument_string == identity_arguments(privileged=False)
    assert "192.168.1.14" not in request.argument_string


# ---------------------------------------------------------------------------
# mDNS: the devices that answer to a name without any DNS record
# ---------------------------------------------------------------------------
def _mdns_response(name: str, *, compressed: bool = False) -> bytes:
    """A real mDNS PTR response for 192.168.1.14, as a responder sends it."""
    question = _encode_question("14.1.168.192.in-addr.arpa")
    answer_name = b"\xc0\x0c" if compressed else question  # pointer to offset 12
    labels = _encode_question(name)
    return (
        b"\x00\x00\x84\x00"          # id 0, flags: response + authoritative
        b"\x00\x01\x00\x01\x00\x00\x00\x00"  # 1 question, 1 answer
        + question
        + b"\x00\x0c\x00\x01"        # QTYPE PTR, QCLASS IN
        + answer_name
        + b"\x00\x0c\x00\x01"        # TYPE PTR, CLASS IN
        + b"\x00\x00\x00\x78"        # TTL 120
        + len(labels).to_bytes(2, "big")
        + labels
    )


def test_an_mdns_answer_is_read() -> None:
    """The case NetBIOS and SMB do not cover: an Apple or Avahi device."""
    assert _first_ptr_answer(_mdns_response("macbook-pro.local")) == (
        "macbook-pro.local"
    )


def test_a_compressed_answer_name_is_followed() -> None:
    """Responders compress the repeated question name into a pointer."""
    assert _first_ptr_answer(
        _mdns_response("printer.local", compressed=True)
    ) == "printer.local"


@pytest.mark.parametrize(
    "payload",
    [
        b"",                                    # nothing at all
        b"\x00" * 8,                            # shorter than a header
        b"\x00\x00\x84\x00\x00\x01\x00\x00" + b"\x00" * 4,  # no answers
        # A name whose length byte runs past the end of the packet.
        b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x40abc",
        # A compression pointer aimed at itself: the loop a naive decoder
        # never leaves, driven entirely by data received off the network.
        b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0\x0c",
    ],
)
def test_a_malformed_response_yields_nothing_and_does_not_hang(
    payload: bytes,
) -> None:
    """A UDP answer is unauthenticated input; it must not be trusted to end."""
    assert _first_ptr_answer(payload) == ""


def test_mdns_lookup_of_a_non_address_is_refused_without_a_socket() -> None:
    """No packet leaves the machine for something that is not an address."""
    assert mdns_hostname("not-an-address", timeout=0.01) == ""


# ---------------------------------------------------------------------------
# The shape is python-nmap's, not this test file's
# ---------------------------------------------------------------------------
#: Nmap's own XML for a Windows host that answered every question. Run through
#: python-nmap's parser rather than hand-built into a dict, because the risk
#: worth guarding against is the library's output shape differing from what
#: the parser assumes - a hand-written fixture would agree with the parser by
#: construction and prove nothing.
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O" start="1755870000" version="7.94">
<host><status state="up" reason="arp-response"/>
<address addr="192.168.1.14" addrtype="ipv4"/>
<address addr="3C:52:82:1A:0B:7E" addrtype="mac" vendor="Intel Corporate"/>
<hostnames><hostname/></hostnames>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds" method="table" conf="3"/></port></ports>
<os><osmatch name="Microsoft Windows 10 1909 - 21H1" accuracy="95" line="69277">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="10"
 accuracy="95"><cpe>cpe:/o:microsoft:windows_10</cpe></osclass></osmatch></os>
<hostscript>
<script id="nbstat" output="NetBIOS name: LAPTOP-ABC123, NetBIOS user: &lt;unknown&gt;,\
 NetBIOS MAC: 3c:52:82:1a:0b:7e (Intel Corporate)"/>
<script id="smb-os-discovery" output="&#xa;  OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)\
&#xa;  OS CPE: cpe:/o:microsoft:windows_10::-&#xa;  Computer name: LAPTOP-ABC123\
&#xa;  Domain name: WORKGROUP&#xa;"/>
</hostscript>
<times srtt="200" rttvar="100" to="100000"/></host>
<runstats><finished time="1755870010" elapsed="10"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>"""


@pytest.fixture(name="library_entry")
def _library_entry() -> dict[str, object]:
    """The host entry python-nmap builds from that XML."""
    nmap = pytest.importorskip("nmap", reason="python-nmap is not installed")
    parsed = nmap.PortScanner().analyse_nmap_xml_scan(nmap_xml_output=NMAP_XML)
    return parsed["scan"]["192.168.1.14"]


def test_the_parser_reads_what_the_library_actually_emits(
    library_entry: dict[str, object],
) -> None:
    """Both fields resolve from a real Nmap document, end to end."""
    identity = identity_from_scan(library_entry)
    assert identity.hostname == "LAPTOP-ABC123"
    assert identity.os_name == "Windows 10 Pro 19041 (Windows 10 Pro 6.3)"
    assert identity.os_cpe == "cpe:/o:microsoft:windows_10::-"
    assert identity.os_version == "10"
    assert not identity.notes


def test_accuracy_survives_arriving_as_a_string(
    library_entry: dict[str, object],
) -> None:
    """python-nmap yields ``accuracy='95'``; the column is an integer."""
    assert library_entry["osmatch"][0]["accuracy"] == "95"  # the library's type
    assert parse_os_match(library_entry)["accuracy"] == 95  # ours


def test_cpe_survives_arriving_as_a_list(
    library_entry: dict[str, object],
) -> None:
    """``osclass`` nests CPEs in a list even when there is only one."""
    assert library_entry["osmatch"][0]["osclass"][0]["cpe"] == [
        "cpe:/o:microsoft:windows_10"
    ]
    assert parse_os_match(library_entry)["cpe"] == "cpe:/o:microsoft:windows_10"


# ---------------------------------------------------------------------------
# The whole path, with a fake runner standing in for Nmap
# ---------------------------------------------------------------------------
class _FakeRunResult:
    def __init__(self, scan_data: dict[str, object]) -> None:
        self.scan_data = scan_data
        self.command_line = "nmap (fake)"
        self.nmap_version = "Nmap 7.94"
        self.duration_seconds = 0.1
        self.stderr = ""


class _FakeRunner:
    """Returns a recorded Nmap answer without touching the network."""

    def __init__(self, entry: dict[str, object]) -> None:
        self._entry = entry
        self.requests: list[object] = []

    def run(self, request: object) -> _FakeRunResult:
        self.requests.append(request)
        return _FakeRunResult({"scan": {request.target: self._entry}})


@pytest.fixture(name="no_network")
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Silence the resolver fallbacks so no test reaches a real network.

    Without this the fallback chain genuinely queries DNS and mDNS for the
    address in the fixture, which makes the test slow, machine-dependent, and
    a source of traffic nobody asked a test suite to send.
    """
    from aethra_sec.services import nmap_service

    monkeypatch.setattr(nmap_service, "reverse_dns", lambda address, **_: "")
    monkeypatch.setattr(nmap_service, "mdns_hostname", lambda address, **_: "")


def _service_probe(host: ScanHostResult, entry: dict[str, object]) -> _FakeRunner:
    """Drive ``NmapService._discover_one_identity`` against a recorded answer."""
    from aethra_sec.services.nmap_service import NmapService

    runner = _FakeRunner(entry)
    NmapService._discover_one_identity(object.__new__(NmapService), host, runner)
    return runner


def test_the_probe_fills_the_two_empty_columns(no_network: None) -> None:
    """End to end: the exact failing host, now named and identified."""
    host = ScanHostResult(
        ip_address="192.168.1.14",
        mac_address="3C:52:82:1A:0B:7E",
        status=HostStatus.UP,
    )
    assert host.hostname_text == NOT_DETECTED and host.os_text == NOT_DETECTED

    _service_probe(host, _host_entry(smb=SMB_OUTPUT, nbstat=NBSTAT_OUTPUT))

    assert host.hostname == "LAPTOP-ABC123"
    assert host.hostname_source == "SMB"
    assert host.os_name == "Windows 10 Pro 19041 (Windows 10 Pro 6.3)"
    assert host.os_cpe == "cpe:/o:microsoft:windows_10::-"
    assert host.os_source == "SMB"
    # The port-scan results are untouched by the follow-up probe.
    assert host.mac_address == "3C:52:82:1A:0B:7E"


def test_the_probe_never_overwrites_what_the_scan_already_found(
    no_network: None,
) -> None:
    """A follow-up adds what is missing; it does not revise what is there."""
    host = ScanHostResult(
        ip_address="192.168.1.14",
        hostname="already-known",
        os_name="Already Identified OS",
        status=HostStatus.UP,
    )
    _service_probe(host, _host_entry(smb=SMB_OUTPUT))
    assert host.hostname == "already-known"
    assert host.os_name == "Already Identified OS"


WINDOWS_SCAN_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV --top-ports 1000" version="7.94">
<host><status state="up" reason="arp-response"/>
<address addr="192.168.1.14" addrtype="ipv4"/>
<address addr="3C:52:82:1A:0B:7E" addrtype="mac" vendor="Intel Corporate"/>
<hostnames><hostname/></hostnames>
<ports>
<port protocol="tcp" portid="135">
<state state="open" reason="syn-ack" reason_ttl="128"/>
<service name="msrpc" product="Microsoft Windows RPC" ostype="Windows"/></port>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack" reason_ttl="128"/>
<service name="microsoft-ds"/></port>
</ports></host>
<runstats><finished time="1755870010"/></runstats></nmaprun>"""


def test_the_os_column_fills_when_neither_fingerprint_nor_smb_can_run(
    no_network: None,
) -> None:
    """The situation most operators are actually in.

    No Administrator rights, so Nmap emitted no fingerprint; a host that will
    not hold an anonymous SMB session, so ``smb-os-discovery`` said nothing.
    The column read Unknown - while the scan's own port results had already
    recorded ``Microsoft Windows RPC`` and a reply TTL of 128.
    """
    host = ScanHostResult(
        ip_address="192.168.1.14",
        mac_address="3C:52:82:1A:0B:7E",
        status=HostStatus.UP,
    )
    assert host.os_text == NOT_DETECTED

    from aethra_sec.services.nmap_service import NmapService

    NmapService._discover_one_identity(
        object.__new__(NmapService),
        host,
        _FakeRunner(_host_entry()),      # the probe itself finds nothing
        WINDOWS_SCAN_XML,                # but the port scan already knew
    )

    assert host.os_family == "Windows"
    assert host.os_source == "scan evidence"
    assert host.os_accuracy and host.os_accuracy > 0
    assert host.os_text != NOT_DETECTED
    # The conclusion has to be checkable, so the evidence travels with it.
    assert any("Operating system from" in note for note in host.identity_notes)


def test_inference_never_overwrites_a_real_fingerprint(no_network: None) -> None:
    """Evidence fills a blank. It does not revise what Nmap actually measured."""
    host = ScanHostResult(
        ip_address="192.168.1.14",
        os_name="Microsoft Windows 10 1909 - 21H1",
        os_accuracy=95,
        status=HostStatus.UP,
    )
    from aethra_sec.services.nmap_service import NmapService

    NmapService._discover_one_identity(
        object.__new__(NmapService), host, _FakeRunner(_host_entry()),
        WINDOWS_SCAN_XML,
    )
    assert host.os_name == "Microsoft Windows 10 1909 - 21H1"
    assert host.os_accuracy == 95
    assert host.os_source != "scan evidence"


def test_a_host_that_answers_nothing_keeps_its_scan_results(
    no_network: None,
) -> None:
    """Failure to name a host is recorded, not escalated into a scan failure."""
    host = ScanHostResult(ip_address="192.168.1.14", status=HostStatus.UP)
    _service_probe(host, _host_entry())
    assert host.hostname == "" and host.os_name == ""
    assert host.hostname_text == NOT_DETECTED and host.os_text == NOT_DETECTED
    assert host.identity_notes  # the reasons are kept for the operator
