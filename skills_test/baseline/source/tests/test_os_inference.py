"""Identifying an operating system without raw-socket privileges.

Nmap's ``-O`` fingerprint needs raw sockets - Administrator on Windows, root
on Linux - so for most people running this it never executes, and
``smb-os-discovery`` only answers on a host that will hold an anonymous SMB
session. Between them they leave the Operating system column reading Unknown
on most scans, which is honest and useless: the operator asked what the
machine is.

They are rarely short of evidence. A service scan already collects several
things that name an operating system, and ``python-nmap`` discards three of
them while building its result dictionary - the reply TTL, the service
``ostype`` attribute, and every service CPE but the last. Reading Nmap's own
XML recovers them.

What is pinned here:

* the fields python-nmap drops are genuinely read back out of the XML;
* real banner formats are matched, including the ones with no word boundary
  to anchor on (``0ubuntu0.24.04.1``) that a naive pattern silently misses;
* a service that names no platform produces no claim - ``nginx 1.24.0`` is not
  evidence of anything;
* stronger evidence outranks weaker, and the confidence reported actually
  differs between them;
* a reply TTL narrows a family and is never promoted into a version;
* a TTL that disagrees with the banner is surfaced, not hidden;
* malformed XML costs the scan its OS evidence and nothing else.
"""

from __future__ import annotations

import pytest

from aethra_sec.integrations.nmap.osfingerprint import (
    CONFIDENCE_BANNER,
    CONFIDENCE_OS_CPE,
    CONFIDENCE_OSTYPE,
    CONFIDENCE_TTL,
    OsEvidence,
    infer_os,
    os_family_from_ttl,
    os_from_banner,
    parse_xml_evidence,
)


def _xml(ports: str, address: str = "192.168.1.14") -> str:
    """One Nmap document for one host with the given ``<port>`` elements."""
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1755870000" version="7.94">
<host><status state="up" reason="arp-response"/>
<address addr="{address}" addrtype="ipv4"/>
<hostnames><hostname/></hostnames>
<ports>{ports}</ports>
</host>
<runstats><finished time="1755870010"/></runstats></nmaprun>"""


# ---------------------------------------------------------------------------
# The fields python-nmap throws away
# ---------------------------------------------------------------------------
def test_reply_ttl_is_recovered_from_the_xml() -> None:
    """python-nmap drops reason_ttl entirely; it is on every port in every scan."""
    evidence = parse_xml_evidence(
        _xml(
            '<port protocol="tcp" portid="445">'
            '<state state="open" reason="syn-ack" reason_ttl="128"/>'
            '<service name="microsoft-ds"/></port>'
        ),
        "192.168.1.14",
    )
    assert evidence.ttls == [128]


def test_service_ostype_is_recovered_from_the_xml() -> None:
    """python-nmap never reads the attribute, and it names the platform."""
    evidence = parse_xml_evidence(
        _xml(
            '<port protocol="tcp" portid="135">'
            '<state state="open" reason="syn-ack" reason_ttl="128"/>'
            '<service name="msrpc" product="Microsoft Windows RPC" '
            'ostype="Windows"/></port>'
        ),
        "192.168.1.14",
    )
    assert evidence.ostypes == ["Windows"]


def test_every_os_cpe_is_recovered_not_only_the_last() -> None:
    """python-nmap keeps one CPE per service; a service can report several."""
    evidence = parse_xml_evidence(
        _xml(
            '<port protocol="tcp" portid="445">'
            '<state state="open" reason="syn-ack" reason_ttl="128"/>'
            '<service name="microsoft-ds">'
            "<cpe>cpe:/a:microsoft:windows_server_2019</cpe>"
            "<cpe>cpe:/o:microsoft:windows_server_2019</cpe>"
            "</service></port>"
        ),
        "192.168.1.14",
    )
    # Only the /o: entry is an operating system; /a: is the application.
    assert evidence.os_cpes == ["cpe:/o:microsoft:windows_server_2019"]


def test_evidence_for_another_host_is_not_borrowed() -> None:
    """A subnet scan puts many hosts in one document."""
    evidence = parse_xml_evidence(
        _xml(
            '<port protocol="tcp" portid="445">'
            '<state state="open" reason="syn-ack" reason_ttl="128"/>'
            '<service name="microsoft-ds" ostype="Windows"/></port>',
            address="192.168.1.99",
        ),
        "192.168.1.14",
    )
    assert evidence.is_empty


@pytest.mark.parametrize(
    "text", ["", "not xml at all", "<nmaprun><host>", "<?xml version='1.0'?>"]
)
def test_unreadable_xml_costs_only_the_os_evidence(text: str) -> None:
    """The port results are already good; losing them to a parse error is worse."""
    assert parse_xml_evidence(text, "192.168.1.14").is_empty


def test_a_locally_generated_ttl_of_zero_is_not_evidence() -> None:
    """Loopback answers report TTL 0, which says nothing about an initial value."""
    evidence = parse_xml_evidence(
        _xml(
            '<port protocol="tcp" portid="3306">'
            '<state state="open" reason="syn-ack" reason_ttl="0"/>'
            '<service name="mysql"/></port>'
        ),
        "192.168.1.14",
    )
    assert evidence.ttls == []


# ---------------------------------------------------------------------------
# Banners - real formats, including the ones a naive pattern misses
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        # The trap: "ubuntu" is preceded by a digit, so \bubuntu never matches,
        # and the release sits after "ubuntu0." rather than before it.
        ("MySQL 5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1", "Ubuntu 24.04"),
        ("OpenSSH 8.9p1 Ubuntu-3ubuntu0.4 Ubuntu Linux; protocol 2.0", "Ubuntu"),
        ("OpenSSH 9.2p1 Debian 2+deb12u2 Debian Linux; protocol 2.0", "Debian 12"),
        ("Apache httpd 2.4.57 (Debian)", "Debian"),
        ("OpenSSH 8.0 (protocol 2.0) .el8_6", "Red Hat / CentOS 8"),
        ("Microsoft Windows RPC", "Windows"),
        ("Microsoft IIS httpd 10.0", "Windows (IIS 10.0)"),
        ("Microsoft-IIS/10.0", "Windows (IIS 10.0)"),
        ("Microsoft Windows Server 2019 microsoft-ds", "Windows Server 2019"),
        ("OpenSSH for_Windows_8.1 (protocol 2.0)", "Windows"),
        ("Apple macOS Darwin 21.6.0", "macOS"),
    ],
)
def test_banners_that_name_a_platform(banner: str, expected: str) -> None:
    """Each of these is text Nmap actually emits."""
    assert os_from_banner(banner).name == expected


@pytest.mark.parametrize(
    "banner",
    [
        "nginx 1.24.0",
        "MySQL 8.0.35",
        "Postfix smtpd",
        "",
        "vsftpd 3.0.5",
    ],
)
def test_a_banner_that_names_no_platform_claims_nothing(banner: str) -> None:
    """Cross-platform software is not evidence of an operating system."""
    assert not os_from_banner(banner).found


def test_samba_rules_windows_out_rather_than_in() -> None:
    """Samba is the Unix implementation of SMB - a Windows box uses its own."""
    guess = os_from_banner("Samba smbd 4.6.2")
    assert guess.family == "Linux"
    assert "Samba" in guess.name


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ttl", "expected"),
    [
        (64, "Linux/Unix"),
        (57, "Linux/Unix"),    # 64 less seven hops
        (128, "Windows"),
        (119, "Windows"),      # 128 less nine hops
        (255, "Network device"),
        (250, "Network device"),
    ],
)
def test_ttl_narrows_the_family(ttl: int, expected: str) -> None:
    """An observed TTL is the initial value minus the hop count."""
    assert os_family_from_ttl([ttl]).name == expected


def test_the_least_travelled_reply_is_used() -> None:
    """The highest observation crossed the fewest hops, so it is closest."""
    assert os_family_from_ttl([54, 64, 60]).name == "Linux/Unix"


def test_a_ttl_never_becomes_a_version() -> None:
    """A hop count identifies a family. It cannot identify a build."""
    guess = os_family_from_ttl([128])
    assert guess.version == ""
    assert guess.confidence == CONFIDENCE_TTL
    assert "narrows the family only" in guess.basis


def test_no_usable_ttl_yields_no_claim() -> None:
    """Silence is not evidence."""
    assert not os_family_from_ttl([]).found
    assert not os_family_from_ttl([0, 0]).found


# ---------------------------------------------------------------------------
# Precedence, and how sure each answer is
# ---------------------------------------------------------------------------
def test_an_os_cpe_outranks_everything_else() -> None:
    """Nmap naming the operating system beats any inference from it."""
    guess = infer_os(
        OsEvidence(
            os_cpes=["cpe:/o:microsoft:windows_10:1909"],
            ostypes=["Windows"],
            ttls=[128],
            banners=[("http", "nginx 1.24.0")],
        )
    )
    assert guess.confidence == CONFIDENCE_OS_CPE
    assert guess.cpe == "cpe:/o:microsoft:windows_10:1909"
    assert guess.version == "1909"
    assert guess.family == "Windows"


def test_ostype_outranks_a_banner() -> None:
    """Nmap's service database is a stronger source than free text."""
    guess = infer_os(
        OsEvidence(ostypes=["Windows"], banners=[("http", "nginx 1.24.0")])
    )
    assert guess.name == "Windows"
    assert guess.confidence == CONFIDENCE_OSTYPE


def test_a_banner_outranks_a_ttl() -> None:
    """A version from a banner beats a family from a hop count."""
    guess = infer_os(
        OsEvidence(
            ttls=[64],
            banners=[("mysql", "MySQL 5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1")],
        )
    )
    assert guess.name == "Ubuntu 24.04"
    assert guess.confidence == CONFIDENCE_BANNER


def test_the_most_specific_banner_wins() -> None:
    """A version is worth more than a bare family, whichever port carried it."""
    guess = infer_os(
        OsEvidence(
            banners=[
                ("msrpc", "Microsoft Windows RPC"),
                ("http", "Microsoft IIS httpd 10.0"),
            ]
        )
    )
    assert guess.name == "Windows (IIS 10.0)"


def test_confidence_actually_separates_the_sources() -> None:
    """An operator deciding whether to act needs these to differ."""
    assert CONFIDENCE_OS_CPE > CONFIDENCE_OSTYPE > CONFIDENCE_BANNER
    assert CONFIDENCE_BANNER > CONFIDENCE_TTL
    # A TTL must not read as a confident answer.
    assert CONFIDENCE_TTL < 50


def test_a_ttl_alone_is_still_an_answer() -> None:
    """A host that answered nothing else still has its family narrowed."""
    guess = infer_os(OsEvidence(ttls=[128]))
    assert guess.name == "Windows"
    assert guess.confidence == CONFIDENCE_TTL


def test_no_evidence_produces_no_guess() -> None:
    """Where there is nothing, the caller reports Unknown."""
    assert not infer_os(OsEvidence()).found


# ---------------------------------------------------------------------------
# Corroboration and contradiction
# ---------------------------------------------------------------------------
def test_an_agreeing_ttl_is_noted() -> None:
    """Linux, macOS and BSD all use TTL 64, so 64 agrees with all of them."""
    for family_banner in (
        "Apache httpd 2.4.57 (Debian)",
        "Apple macOS Darwin 21.6.0",
    ):
        guess = infer_os(OsEvidence(ttls=[64], banners=[("x", family_banner)]))
        assert "reply TTL agrees" in guess.basis


def test_a_contradicting_ttl_is_surfaced_not_hidden() -> None:
    """A Windows banner behind a TTL-64 reply usually means something relayed it."""
    guess = infer_os(
        OsEvidence(ttls=[64], banners=[("msrpc", "Microsoft Windows RPC")])
    )
    assert guess.name == "Windows"
    assert "proxy or gateway" in guess.basis


def test_the_inventory_keeps_the_best_answer_not_the_latest() -> None:
    """An unprivileged re-scan must not replace a measured fingerprint.

    Answers now arrive with very different confidence behind them. Without a
    guard, running the same scan again without Administrator rights would
    quietly overwrite a 98%-accuracy ``-O`` fingerprint with a 45% hop-count
    inference, and the inventory would get worse the more it was scanned.
    """
    import inspect

    from aethra_sec.database.repositories.hosts import HostRepository

    source = inspect.getsource(HostRepository._update_os)
    assert "COALESCE(os_accuracy, 0) <= %s" in source
    assert "os_name = ''" in source


def test_the_basis_always_states_the_evidence() -> None:
    """A conclusion an operator cannot check is not worth showing."""
    for evidence in (
        OsEvidence(os_cpes=["cpe:/o:microsoft:windows_10"]),
        OsEvidence(ostypes=["Windows"]),
        OsEvidence(banners=[("http", "Microsoft IIS httpd 10.0")]),
        OsEvidence(ttls=[128]),
    ):
        assert infer_os(evidence).basis.strip()
