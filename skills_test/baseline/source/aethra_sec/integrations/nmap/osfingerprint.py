"""Operating system inference from evidence a scan already collected (§47).

Nmap's ``-O`` fingerprint is the direct way to identify an operating system,
and it is unavailable to most people running this: it needs raw sockets, which
means Administrator on Windows or root on Linux. Telling an operator "Unknown -
run as Administrator" is accurate and useless. They asked what the machine is.

They are usually not short of evidence, only of anything reading it. A service
scan already collects several things that name an operating system outright,
and two of them never reach the application because ``python-nmap`` discards
them when it builds its result dictionary:

* **Service CPEs.** ``-sV`` attaches a CPE to a matched service, and some of
  those are ``cpe:/o:`` - an *operating system* CPE, Nmap stating the OS
  directly. python-nmap keeps only the last CPE per service and drops the rest.
* **The service ``ostype`` attribute.** Nmap writes ``ostype="Windows"`` on a
  service element when its fingerprint database knows the platform. python-nmap
  does not read the attribute at all.
* **``reason_ttl``.** Every port in every scan carries the TTL of the packet
  that answered. Initial TTLs are conventional - 64 on Linux and Unix, 128 on
  Windows, 255 on most network equipment - so the value narrows the family
  even for a host that answered nothing else. python-nmap drops this too.
* **Version banners.** A service often states the distribution in plain text:
  ``5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1`` names Ubuntu 24.04.

So this module reads the raw Nmap XML for the fields the library throws away,
and infers what it can. Every answer carries its evidence and a confidence, and
the confidence is genuinely lower for the weaker signals - a TTL narrows a
family, it does not identify a build. Nothing here contacts the host: it is
pure analysis of a scan that already ran.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.nmap.osfingerprint")

#: Conventional initial TTLs, smallest first. An observed TTL is the initial
#: value minus the hop count, so the initial value is the smallest conventional
#: TTL that is not below what was observed.
INITIAL_TTLS: tuple[tuple[int, str, str], ...] = (
    (64, "Linux/Unix", "Linux, macOS, BSD and Android all start at 64"),
    (128, "Windows", "Windows starts at 128"),
    (255, "Network device", "routers, switches and printers commonly start at 255"),
)

#: Confidence for each class of evidence. These are deliberately not close
#: together: an operator deciding whether to act on "Windows" needs to know
#: whether a service said so or whether a hop count implied it.
CONFIDENCE_OS_CPE = 95
CONFIDENCE_OSTYPE = 85
CONFIDENCE_BANNER = 80
CONFIDENCE_TTL = 45


@dataclass
class OsEvidence:
    """What one host's scan revealed that bears on its operating system."""

    os_cpes: list[str] = field(default_factory=list)
    ostypes: list[str] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)
    #: ``(service name, full banner text)`` for every service that answered.
    banners: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True when the scan found nothing that speaks to an OS."""
        return not (self.os_cpes or self.ostypes or self.ttls or self.banners)


@dataclass
class OsGuess:
    """An operating system conclusion, with what it rests on."""

    name: str = ""
    family: str = ""
    version: str = ""
    cpe: str = ""
    confidence: int = 0
    #: Plain-language statement of the evidence, shown to the operator.
    basis: str = ""

    @property
    def found(self) -> bool:
        """True when an operating system was actually identified."""
        return bool(self.name)


# ---------------------------------------------------------------------------
# Reading the XML python-nmap threw away
# ---------------------------------------------------------------------------
def parse_xml_evidence(xml_text: str, address: str) -> OsEvidence:
    """Collect OS evidence for one address from raw Nmap XML.

    Args:
        xml_text: the document ``PortScanner.get_nmap_last_output()`` returns.
        address: the host to collect evidence for.

    Returns:
        Everything found. Malformed XML yields empty evidence rather than an
        exception - a scan's port results are still good when its OS evidence
        cannot be read, and losing them to a parse error would be the wrong
        trade.
    """
    evidence = OsEvidence()
    if not xml_text:
        return evidence
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        LOGGER.debug("Could not parse Nmap XML for OS evidence: %s", exc)
        return evidence

    for host in root.iter("host"):
        if not _host_has_address(host, address):
            continue
        for port in host.iter("port"):
            _collect_state(port, evidence)
            _collect_service(port, evidence)
    return evidence


def _host_has_address(host: ElementTree.Element, address: str) -> bool:
    """True when this ``<host>`` element is the address we are looking at."""
    return any(
        element.get("addr") == address for element in host.iter("address")
    )


def _collect_state(port: ElementTree.Element, evidence: OsEvidence) -> None:
    """Record the TTL of the packet that answered on this port."""
    state = port.find("state")
    if state is None:
        return
    try:
        ttl = int(state.get("reason_ttl") or 0)
    except ValueError:
        return
    # A TTL of 0 is what a locally generated answer reports; it carries no
    # information about a remote host's initial value.
    if 0 < ttl <= 255:
        evidence.ttls.append(ttl)


def _collect_service(port: ElementTree.Element, evidence: OsEvidence) -> None:
    """Record every OS signal attached to this port's service."""
    service = port.find("service")
    if service is None:
        return

    ostype = (service.get("ostype") or "").strip()
    if ostype:
        evidence.ostypes.append(ostype)

    for cpe in service.iter("cpe"):
        text = (cpe.text or "").strip()
        # Only ``cpe:/o:`` is an operating system. ``cpe:/a:`` is the
        # application, which says nothing about what it runs on.
        if text.startswith("cpe:/o:"):
            evidence.os_cpes.append(text)

    banner = " ".join(
        part
        for part in (
            service.get("product"),
            service.get("version"),
            service.get("extrainfo"),
        )
        if part
    ).strip()
    if banner:
        evidence.banners.append(((service.get("name") or "").strip(), banner))


# ---------------------------------------------------------------------------
# Reading a distribution out of a banner
# ---------------------------------------------------------------------------
#: Ordered banner patterns. The first match wins, so the specific ones - those
#: that carry a version - come before the ones that only name a family. Every
#: pattern here is drawn from text Nmap actually emits.
_BANNER_RULES: tuple[tuple[str, str, str, str], ...] = (
    # (regex, family, name template, version group name or "")
    #
    # Debian and Ubuntu package versions embed the release, but never at a word
    # boundary: MariaDB reports "5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1",
    # where the release 24.04 sits after "ubuntu0." and "ubuntu" itself is
    # preceded by a digit. Anchoring on \b finds none of it.
    (r"ubuntu[0-9]*[.\-~](?P<v>\d{2}\.\d{2})", "Linux", "Ubuntu {v}", "v"),
    (r"ubuntu", "Linux", "Ubuntu", ""),
    (r"[~+-]deb(?P<v>\d+)u\d+", "Linux", "Debian {v}", "v"),
    (r"\bdebian\b", "Linux", "Debian", ""),
    (r"\.el(?P<v>\d+)", "Linux", "Red Hat / CentOS {v}", "v"),
    (r"\b(?:centos|red\s*hat|rhel)\b", "Linux", "Red Hat / CentOS", ""),
    (r"\b(?:fedora|fc\d+)\b", "Linux", "Fedora", ""),
    (r"\b(?:suse|sles)\b", "Linux", "SUSE", ""),
    (r"\balpine\b", "Linux", "Alpine Linux", ""),
    (r"\braspbian\b", "Linux", "Raspberry Pi OS", ""),
    (r"openssh[-_ ]?for[-_ ]?windows", "Windows", "Windows", ""),
    (r"\bwindows\s+server\s+(?P<v>\d{4})", "Windows", "Windows Server {v}", "v"),
    (r"\bwindows\s+(?P<v>1[01]|8\.1|8|7|xp|vista)\b", "Windows", "Windows {v}", "v"),
    # Nmap writes "Microsoft IIS httpd 10.0"; the HTTP header form is
    # "Microsoft-IIS/10.0". Both appear, depending on which one matched.
    (
        r"microsoft[-\s]?iis(?:\s+httpd)?[/\s](?P<v>[\d.]+)",
        "Windows",
        "Windows (IIS {v})",
        "v",
    ),
    (r"\bmicrosoft\b|\bwin(?:32|64)\b|\bwindows\b", "Windows", "Windows", ""),
    (r"\bfreebsd\b", "BSD", "FreeBSD", ""),
    (r"\bopenbsd\b", "BSD", "OpenBSD", ""),
    (r"\bnetbsd\b", "BSD", "NetBSD", ""),
    (r"\bdarwin\b|\bmac\s*os\b", "macOS", "macOS", ""),
    # Samba is the Unix implementation of SMB, so its presence rules Windows
    # out rather than in - a Windows box serves SMB with its own stack.
    (r"\bsamba\b", "Linux", "Linux/Unix (Samba)", ""),
)

_COMPILED_RULES = tuple(
    (re.compile(pattern, re.IGNORECASE), family, template, group)
    for pattern, family, template, group in _BANNER_RULES
)


def os_from_banner(banner: str) -> OsGuess:
    """Read an operating system out of one service banner, if it states one."""
    for pattern, family, template, group in _COMPILED_RULES:
        match = pattern.search(banner)
        if match is None:
            continue
        version = match.group(group) if group else ""
        name = template.format(v=version) if group else template
        return OsGuess(
            name=name,
            family=family,
            version=version,
            confidence=CONFIDENCE_BANNER,
            basis=f"service banner: {banner}",
        )
    return OsGuess()


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------
def os_family_from_ttl(ttls: list[int]) -> OsGuess:
    """Narrow the family from the TTLs that answered.

    An observed TTL is the initial value minus the number of hops, so the
    initial value is the smallest conventional TTL at or above what was seen.
    The *highest* observation is used because it has traversed the fewest
    hops and so is closest to the value the host actually set.

    This identifies a family, never a build, and says so.
    """
    usable = [ttl for ttl in ttls if 0 < ttl <= 255]
    if not usable:
        return OsGuess()
    observed = max(usable)
    for initial, family, why in INITIAL_TTLS:
        if observed <= initial:
            return OsGuess(
                name=family,
                family=family if family != "Network device" else "",
                confidence=CONFIDENCE_TTL,
                basis=(
                    f"reply TTL {observed}, consistent with an initial TTL of "
                    f"{initial} ({why}). This narrows the family only - it "
                    "does not identify a version."
                ),
            )
    return OsGuess()


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------
def infer_os(evidence: OsEvidence) -> OsGuess:
    """Best available conclusion from everything the scan collected.

    Sources are tried strongest first: an OS CPE is Nmap naming the operating
    system, a banner is the software naming its own platform, and a TTL is an
    inference from a hop count. Where nothing supports a conclusion, an empty
    guess is returned and the caller reports Unknown - a weak signal is
    reported as weak, never promoted to fill a blank cell.
    """
    for source in (_from_os_cpe, _from_ostype, _from_banners):
        guess = source(evidence)
        if guess.found:
            # A TTL cannot beat a named OS, but it can corroborate one, and a
            # contradiction is worth showing rather than hiding.
            return _annotate_with_ttl(guess, evidence)
    return os_family_from_ttl(evidence.ttls)


def _from_os_cpe(evidence: OsEvidence) -> OsGuess:
    """Use an ``cpe:/o:`` a service reported - Nmap naming the OS outright."""
    if not evidence.os_cpes:
        return OsGuess()
    cpe = evidence.os_cpes[0]
    parts = cpe.split(":")
    vendor = parts[2] if len(parts) > 2 else ""
    product = parts[3].replace("_", " ") if len(parts) > 3 else ""
    version = parts[4] if len(parts) > 4 else ""
    name = " ".join(part for part in (vendor.title(), product.title()) if part)
    return OsGuess(
        name=name or cpe,
        family=_family_for(f"{vendor} {product}"),
        version=version,
        cpe=cpe,
        confidence=CONFIDENCE_OS_CPE,
        basis=f"operating system CPE reported by a service: {cpe}",
    )


def _from_ostype(evidence: OsEvidence) -> OsGuess:
    """Use the ``ostype`` Nmap attached to a matched service."""
    if not evidence.ostypes:
        return OsGuess()
    ostype = evidence.ostypes[0]
    return OsGuess(
        name=ostype,
        family=_family_for(ostype),
        confidence=CONFIDENCE_OSTYPE,
        basis=f"Nmap's service database reports this service runs on {ostype}",
    )


def _from_banners(evidence: OsEvidence) -> OsGuess:
    """Use the most specific banner that names a platform.

    A banner carrying a version is preferred over one that only names a
    family, whichever port it came from.
    """
    best = OsGuess()
    for service_name, banner in evidence.banners:
        guess = os_from_banner(banner)
        if not guess.found:
            continue
        if service_name:
            guess.basis = f"{service_name} banner: {banner}"
        if not best.found or (guess.version and not best.version):
            best = guess
    return best


#: Which families each conventional initial TTL is consistent with. A TTL of
#: 64 does not distinguish Linux from macOS or BSD - they all use it - so all
#: of them count as agreement rather than as a contradiction.
_TTL_COMPATIBLE: dict[str, frozenset[str]] = {
    "Linux/Unix": frozenset({"Linux", "Unix", "BSD", "macOS"}),
    "Windows": frozenset({"Windows"}),
    # 255 is used by network equipment and by some Unix stacks; too weak to
    # contradict anything, so it agrees with whatever was concluded.
    "Network device": frozenset({"Linux", "Unix", "BSD", "macOS", "Windows"}),
}


def _annotate_with_ttl(guess: OsGuess, evidence: OsEvidence) -> OsGuess:
    """Note whether the reply TTL agrees with the conclusion."""
    ttl_guess = os_family_from_ttl(evidence.ttls)
    if not ttl_guess.found or not guess.family:
        return guess
    if guess.family in _TTL_COMPATIBLE.get(ttl_guess.name, frozenset()):
        guess.basis = f"{guess.basis}; reply TTL agrees"
    else:
        # Worth showing: a Windows banner behind a Linux TTL usually means a
        # proxy or a NAT answering, and the operator should know.
        guess.basis = (
            f"{guess.basis}; note the reply TTL suggests {ttl_guess.name}, "
            "which may indicate a proxy or gateway answering for this host"
        )
    return guess


def _family_for(text: str) -> str:
    """Classify free text into an OS family."""
    lowered = text.lower()
    for needle, family in (
        ("windows", "Windows"),
        ("microsoft", "Windows"),
        ("linux", "Linux"),
        ("ubuntu", "Linux"),
        ("debian", "Linux"),
        ("mac", "macOS"),
        ("darwin", "macOS"),
        ("bsd", "BSD"),
        ("solaris", "Unix"),
        ("unix", "Unix"),
    ):
        if needle in lowered:
            return family
    return ""
