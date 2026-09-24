"""Hostname and operating-system discovery for a scanned host (§46, §47).

A port scan answers "what is listening". It does not answer "what is this
machine", and the two are not the same question:

* **Hostname.** Nmap performs a reverse DNS lookup by default, so a host with a
  PTR record is named for free. Most devices on a home or small-office LAN have
  no PTR record at all - the router hands out addresses and never registers
  names - so that lookup returns nothing and the column stays empty. A Windows
  machine in that situation still knows its own name and will tell you, over
  NetBIOS or SMB, if asked.
* **Operating system.** Nmap only fingerprints when it is asked to, with
  ``-O``. A profile without that flag emits no ``osmatch`` element, so there is
  nothing for a parser to find no matter how well written it is.

This module asks both questions properly, using only Nmap's own discovery
scripts and the resolver already on the machine. It performs no exploitation,
no authentication and no credential guessing (§90): ``nbstat`` reads a NetBIOS
name, ``smb-os-discovery`` reads the banner an SMB service volunteers, and
neither logs in.

Nothing here invents an answer. Where a method fails, it is recorded in
:attr:`HostIdentity.notes` so the operator can see *why* a field is unknown
rather than being left to guess.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any

from aethra_sec.integrations.nmap.profiles import (
    DEFAULT_TIMING,
    ScanProfile,
    ScanRequest,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.validation import ValidationError, validate_ip

LOGGER = get_logger("integrations.nmap.identity")

#: Ports the identity probe touches. 135/139/445 are the Windows name and file
#: sharing services; nothing else is contacted.
IDENTITY_PORTS = "135,139,445"

#: Nmap discovery scripts used. Both are in Nmap's "safe"/"discovery"
#: categories - they read what a service offers and do not authenticate.
IDENTITY_SCRIPTS = "nbstat,smb-os-discovery"

#: Ceiling on one host's identity probe. OS fingerprinting is slow, and a scan
#: of a subnet must not stall on a single silent machine.
IDENTITY_TIMEOUT_SECONDS = 90

#: Ceiling on how many hosts one scan will probe individually. A /24 sweep can
#: return 254 live hosts; probing every one of them serially would turn a
#: two-minute scan into a two-hour one. Beyond this the scan finishes with the
#: port results it already has and says so.
IDENTITY_MAX_HOSTS = 64

#: Shown when a field genuinely could not be determined.
UNKNOWN = "Unknown"


@dataclass
class HostIdentity:
    """What could be discovered about one host, and what could not."""

    hostname: str = ""
    hostname_source: str = ""
    os_name: str = ""
    os_version: str = ""
    os_family: str = ""
    os_cpe: str = ""
    os_accuracy: int | None = None
    os_source: str = ""
    #: One line per method that was tried and did not produce an answer.
    notes: list[str] = field(default_factory=list)

    @property
    def found_hostname(self) -> bool:
        """True when a name was actually discovered."""
        return bool(self.hostname)

    @property
    def found_os(self) -> bool:
        """True when an operating system was actually identified."""
        return bool(self.os_name)

    def summary(self) -> str:
        """One line for the log and the scan record."""
        name = self.hostname or UNKNOWN
        system = self.os_name or UNKNOWN
        parts = [f"hostname={name}", f"os={system}"]
        if self.hostname_source:
            parts.append(f"via {self.hostname_source}")
        if self.os_source:
            parts.append(f"os via {self.os_source}")
        return " · ".join(parts)


# ---------------------------------------------------------------------------
# Parsing Nmap's answers
# ---------------------------------------------------------------------------
def _script_output(host_entry: dict[str, Any], script_id: str) -> str:
    """Return one host script's output, or an empty string."""
    scripts = host_entry.get("hostscript") or []
    if not isinstance(scripts, list):
        return ""
    for entry in scripts:
        if isinstance(entry, dict) and entry.get("id") == script_id:
            return str(entry.get("output") or "")
    return ""


def parse_smb_os_discovery(output: str) -> dict[str, str]:
    """Read what an SMB service reported about itself.

    ``smb-os-discovery`` prints labelled lines, for example::

        OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)
        OS CPE: cpe:/o:microsoft:windows_10::-
        Computer name: LAPTOP-ABC123
        NetBIOS computer name: LAPTOP-ABC123\\x00
        Domain name: WORKGROUP

    This is the most trustworthy source available without credentials: the
    machine is stating its own name and version rather than being guessed at
    from packet timings.
    """
    found: dict[str, str] = {}
    for line in output.splitlines():
        text = line.strip()
        if ":" not in text:
            continue
        label, _, value = text.partition(":")
        key = label.strip().lower()
        clean = value.strip().replace("\\x00", "").strip()
        if not clean or clean.lower() in {"<unknown>", "unknown"}:
            continue
        if key == "os":
            found["os"] = clean
        elif key == "os cpe":
            found["cpe"] = clean
        elif key == "computer name":
            found["hostname"] = clean
        elif key == "netbios computer name" and "hostname" not in found:
            found["hostname"] = clean
        elif key == "domain name":
            found["domain"] = clean
    return found


def parse_nbstat(output: str) -> str:
    """Read the NetBIOS name from ``nbstat`` output.

    The script prints, for example::

        NetBIOS name: LAPTOP-ABC123, NetBIOS user: <unknown>, NetBIOS MAC: ...
    """
    match = re.search(r"NetBIOS name:\s*([^,\r\n]+)", output)
    if not match:
        return ""
    name = match.group(1).strip().replace("\\x00", "").strip()
    return "" if name.lower() in {"<unknown>", "unknown"} else name


def parse_os_match(host_entry: dict[str, Any]) -> dict[str, Any]:
    """Read Nmap's OS fingerprint, if it made one.

    Nmap reports its confidence, and reports several candidates when it cannot
    decide. Only the best match is taken, and its accuracy travels with it so
    the interface can show how sure the answer is.
    """
    matches = host_entry.get("osmatch") or []
    if not isinstance(matches, list) or not matches:
        return {}
    best = matches[0]
    if not isinstance(best, dict):
        return {}
    result: dict[str, Any] = {}
    name = str(best.get("name") or "").strip()
    if name:
        result["name"] = name
    try:
        result["accuracy"] = int(best.get("accuracy"))
    except (TypeError, ValueError):
        pass
    classes = best.get("osclass") or []
    if isinstance(classes, list) and classes:
        first = classes[0]
        if isinstance(first, dict):
            family = str(first.get("osfamily") or "").strip()
            if family:
                result["family"] = family
            generation = str(first.get("osgen") or "").strip()
            if generation:
                result["version"] = generation
            cpes = first.get("cpe") or []
            if isinstance(cpes, list) and cpes:
                result["cpe"] = str(cpes[0])
            elif isinstance(cpes, str) and cpes:
                result["cpe"] = cpes
    return result


def parse_ptr_name(host_entry: dict[str, Any]) -> str:
    """Read the reverse-DNS name Nmap resolved, if any."""
    names = host_entry.get("hostnames") or []
    if not isinstance(names, list):
        return ""
    for item in names:
        if isinstance(item, dict):
            candidate = str(item.get("name") or "").strip()
            if candidate:
                return candidate
    return ""


def reverse_dns(address: str, timeout: float = 2.0) -> str:
    """Ask this machine's resolver for a PTR record.

    A second opinion to Nmap's own lookup: the two can differ when Nmap is
    given ``-n`` by a profile, or when a name is only in the local hosts file.
    """
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(address)[0]
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(previous)


# ---------------------------------------------------------------------------
# mDNS
# ---------------------------------------------------------------------------
#: The mDNS port. The query is sent unicast to the host itself rather than to
#: the multicast group, so exactly one machine is contacted - the one being
#: scanned - and no traffic is put on the broadcast domain.
MDNS_PORT = 5353

#: Reverse-lookup record type (PTR) and class (IN) with the mDNS unicast-reply
#: bit set, which asks the responder to answer us directly.
_PTR_TYPE = 12
_IN_CLASS_UNICAST = 0x8001


def _encode_question(name: str) -> bytes:
    """Encode a dotted name as DNS length-prefixed labels."""
    parts = [label.encode("ascii") for label in name.split(".") if label]
    if any(len(label) > 63 for label in parts):
        raise ValueError("DNS label longer than 63 bytes")
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def _decode_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers.

    Returns the name and the offset just past the encoded name in the record
    stream. A pointer is followed at most a bounded number of times, because a
    malformed or hostile response can point at itself and a naive decoder then
    loops forever on data it received from the network.
    """
    labels: list[str] = []
    cursor = offset
    after_pointer: int | None = None
    for _ in range(128):  # bounded: a legal name has far fewer labels
        if cursor >= len(payload):
            break
        length = payload[cursor]
        if length == 0:
            cursor += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if cursor + 1 >= len(payload):
                break
            target = ((length & 0x3F) << 8) | payload[cursor + 1]
            if after_pointer is None:
                after_pointer = cursor + 2
            if target >= cursor:  # only ever points backwards
                break
            cursor = target
            continue
        start = cursor + 1
        end = start + length
        if end > len(payload):
            break
        labels.append(payload[start:end].decode("ascii", "replace"))
        cursor = end
    return ".".join(labels), (after_pointer if after_pointer is not None else cursor)


def mdns_hostname(address: str, timeout: float = 2.0) -> str:
    """Ask a host for its own name over mDNS.

    Apple devices, printers, and any Linux machine running Avahi answer a
    reverse mDNS query with their ``.local`` name even though they have no
    entry in any DNS zone - which is exactly the situation a LAN scan runs
    into. Windows machines generally do not answer this, which is what NetBIOS
    and SMB are for; between the three, most devices can be named.

    This is a read: one UDP question is asked and one answer is read. Nothing
    is registered, announced, or written to the network.

    Returns:
        The name without its trailing dot, or an empty string when the host
        did not answer or answered with nothing.
    """
    try:
        packed = socket.inet_aton(address)
    except OSError:
        return ""
    reverse = ".".join(str(octet) for octet in reversed(packed)) + ".in-addr.arpa"

    try:
        question = _encode_question(reverse)
    except (ValueError, UnicodeEncodeError):
        return ""

    # ID 0 and no flags: an ordinary query, as mDNS specifies.
    query = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + question
        + _PTR_TYPE.to_bytes(2, "big")
        + _IN_CLASS_UNICAST.to_bytes(2, "big")
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (address, MDNS_PORT))
        payload, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    finally:
        sock.close()

    return _first_ptr_answer(payload)


def _first_ptr_answer(payload: bytes) -> str:
    """Read the first PTR name out of a DNS response, or return ''."""
    if len(payload) < 12:
        return ""
    questions = int.from_bytes(payload[4:6], "big")
    answers = int.from_bytes(payload[6:8], "big")
    if answers == 0:
        return ""

    cursor = 12
    for _ in range(min(questions, 8)):
        _, cursor = _decode_name(payload, cursor)
        cursor += 4  # QTYPE + QCLASS

    for _ in range(min(answers, 16)):
        if cursor + 10 > len(payload):
            return ""
        _, cursor = _decode_name(payload, cursor)
        if cursor + 10 > len(payload):
            return ""
        record_type = int.from_bytes(payload[cursor:cursor + 2], "big")
        data_length = int.from_bytes(payload[cursor + 8:cursor + 10], "big")
        data_start = cursor + 10
        if data_start + data_length > len(payload):
            return ""
        if record_type == _PTR_TYPE:
            name, _ = _decode_name(payload, data_start)
            return name.rstrip(".")
        cursor = data_start + data_length
    return ""


# ---------------------------------------------------------------------------
# Putting the answers together
# ---------------------------------------------------------------------------
def identity_from_scan(host_entry: dict[str, Any]) -> HostIdentity:
    """Build a :class:`HostIdentity` from one Nmap host entry.

    Sources are tried in order of how much they can be trusted:

    * a **PTR record** is authoritative for a name, so it wins;
    * **SMB** is the machine describing itself, so it wins for the operating
      system and is the next-best name;
    * a **NetBIOS** name is a name the machine answers to;
    * an **OS fingerprint** is Nmap's inference from packet behaviour, used
      when the host did not say what it runs.
    """
    identity = HostIdentity()

    smb = parse_smb_os_discovery(_script_output(host_entry, "smb-os-discovery"))
    netbios = parse_nbstat(_script_output(host_entry, "nbstat"))
    ptr = parse_ptr_name(host_entry)
    fingerprint = parse_os_match(host_entry)

    # --- hostname ------------------------------------------------------
    if ptr:
        identity.hostname, identity.hostname_source = ptr, "reverse DNS"
    elif smb.get("hostname"):
        identity.hostname, identity.hostname_source = smb["hostname"], "SMB"
    elif netbios:
        identity.hostname, identity.hostname_source = netbios, "NetBIOS"
    else:
        identity.notes.append(
            "No hostname: the address has no PTR record and the host did not "
            "answer NetBIOS, SMB or mDNS name queries."
        )

    # --- operating system ----------------------------------------------
    if smb.get("os"):
        identity.os_name = smb["os"]
        identity.os_source = "SMB"
        identity.os_cpe = smb.get("cpe", "")
        identity.os_version = _version_from_text(smb["os"])
        identity.os_family = _family_from_text(smb["os"])
    elif fingerprint.get("name"):
        identity.os_name = fingerprint["name"]
        identity.os_source = "Nmap fingerprint"
        identity.os_accuracy = fingerprint.get("accuracy")
        identity.os_family = fingerprint.get("family", "")
        identity.os_version = fingerprint.get("version", "")
        identity.os_cpe = fingerprint.get("cpe", "")
    else:
        identity.notes.append(
            "No operating system: SMB reported none and Nmap's fingerprint was "
            "inconclusive. OS fingerprinting needs raw sockets - run as "
            "Administrator on Windows, or as root on Linux."
        )
    return identity


def _version_from_text(text: str) -> str:
    """Pull a version out of an SMB OS string, if one is stated.

    ``smb-os-discovery`` appends the raw protocol version in parentheses::

        Windows 10 Pro 19041 (Windows 10 Pro 6.3)

    That trailing ``6.3`` is the SMB dialect's idea of the NT version, not the
    release the machine is known by. Taking the first dotted number in the
    string finds it and records Windows 10 as version 6.3 - which reads as
    Windows 8.1 to anyone matching a CVE against it. The product is named in
    the head of the string, before the parenthesis, so that is what is read.
    """
    head = text.split("(", 1)[0]
    windows = re.search(
        r"windows\s+(?:server\s+)?(\d{1,4}(?:\.\d+)?|xp|vista|me)\b", head, re.I
    )
    if windows:
        return windows.group(1)
    match = re.search(r"\b(\d+(?:\.\d+){1,3})\b", head) or re.search(
        r"\b(\d+(?:\.\d+){1,3})\b", text
    )
    return match.group(1) if match else ""


def _family_from_text(text: str) -> str:
    """Classify an SMB OS string into a family."""
    lowered = text.lower()
    for needle, family in (
        ("windows", "Windows"), ("linux", "Linux"), ("samba", "Linux"),
        ("mac os", "macOS"), ("darwin", "macOS"), ("unix", "Unix"),
    ):
        if needle in lowered:
            return family
    return ""


def identity_arguments(privileged: bool) -> str:
    """The Nmap arguments the identity probe runs with.

    ``-sV`` is present whether or not the process is privileged, because a
    service banner is the main way an operating system is identified without
    raw sockets: ``Microsoft Windows RPC`` on 135 settles the family on its
    own, and version strings routinely name the distribution outright. Those
    three ports answer for exactly the machines whose name and OS a LAN scan
    otherwise cannot establish.

    Args:
        privileged: whether raw sockets are available. Without them Nmap
            cannot fingerprint, so ``-O`` is left off rather than being passed
            and failing - the NetBIOS and SMB questions still work unprivileged
            and are usually the more useful pair on a LAN anyway.
    """
    parts = [
        "-Pn",                       # the host is already known to be up
        "-sV",                       # banners name the platform (see below)
        f"-p {IDENTITY_PORTS}",
        f"--script {IDENTITY_SCRIPTS}",
        f"--host-timeout {IDENTITY_TIMEOUT_SECONDS}s",
    ]
    if privileged:
        # --osscan-guess makes Nmap offer its closest match instead of
        # refusing when several fingerprints fit. The accuracy it reports
        # travels with the answer, so a guess is never shown as a certainty.
        parts.insert(0, "-O --osscan-guess")
    return " ".join(parts)


#: The identity probe as a first-class profile, so it travels through exactly
#: the same request object, runner and logging as an operator-chosen scan. It
#: is deliberately absent from :data:`PROFILES`: it is not something an
#: operator picks, it is what the service runs on their behalf after a scan.
IDENTITY_PROFILE = ScanProfile(
    key="identity",
    label="Host identity probe",
    description=(
        "Asks a host what it calls itself and what it runs, using NetBIOS and "
        "SMB name queries plus OS fingerprinting where privileges allow. Runs "
        "automatically after a scan for hosts whose name or OS is unknown."
    ),
    arguments=(),
    requires_ports=False,
    default_ports=IDENTITY_PORTS,
    detects_os=True,
    estimated_duration=f"up to {IDENTITY_TIMEOUT_SECONDS}s per host",
)


def identity_request(address: str, privileged: bool) -> ScanRequest:
    """Build the validated request for one host's identity probe.

    The target is re-validated here rather than trusted from the caller, and
    every argument fragment is a constant from this module - none of it comes
    from operator input (§7, §97).

    Args:
        address: the host to probe.
        privileged: whether raw sockets are available, which decides whether
            OS fingerprinting is attempted at all.

    Returns:
        A :class:`ScanRequest` the ordinary :class:`NmapRunner` can execute.

    Raises:
        ValidationError: when ``address`` is not a single valid IP address.
    """
    target = validated_target(address)
    arguments = tuple(identity_arguments(privileged).split())
    return ScanRequest(
        target=target,
        profile=IDENTITY_PROFILE,
        port_spec=IDENTITY_PORTS,
        timing=DEFAULT_TIMING,
        arguments=arguments,
    )


def validated_target(address: str) -> str:
    """Return ``address`` only if it is a single valid IP.

    The identity probe builds a command line, so its target is re-validated
    here rather than trusted from the caller (§7).
    """
    try:
        return validate_ip(address)
    except ValidationError as exc:
        raise ValidationError(
            f"'{address}' is not a valid address for an identity probe: {exc}"
        ) from exc
