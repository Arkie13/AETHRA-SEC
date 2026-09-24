"""Names a device publishes about itself on the wire.

Most consumer hardware has no DNS record. A phone, a tablet or a laptop on a
home or laboratory network answers no reverse lookup, runs no NetBIOS and
holds no PTR entry, so every way of *asking* it for a name comes back empty -
which is why a host inventory built from scans shows "Unknown" for almost
everything on the network.

But those devices are not silent about it. They announce themselves over mDNS
constantly, and the sensor is already capturing those frames. This module
reads the name out of an announcement the device sent about itself.

The rule is deliberately narrow, because a name is identity and a wrong one is
worse than none:

* the frame must be an mDNS **response**. A query names what the sender is
  *looking for* - ``wpad``, ``_googlecast._tcp.local``, another host's address
  - and is evidence about that other name, never about the sender;
* the name must come from an SRV record's **target**, which RFC 2782 defines
  as "the domain name of the target host" - never the service *instance*
  label beside it. Measured against this network's own captures, the targets
  are ``akii.local`` and ``Android_WTKS0CKK.local`` while the instance labels
  for those same two devices include ``I0FRM0j8n14AAA`` and
  ``nearby-presence-nsd-57469620-8721-4106-8e9d-3294c145da98``. An instance
  label is a rotating identifier, and writing one into the inventory as a
  device's name would be inventing identity, not recording it;
* and the name is attributed only to the address the frame was **sent from**.
  A device may answer for a service it hosts, but the announcement still came
  from it.

Nothing is inferred. If a device never announces, it keeps no name, and the
interface says Unknown - which remains the honest answer.
"""

from __future__ import annotations

import re

from aethra_sec.models.traffic import CapturedPacket

#: The mDNS port. A response on any other port is ordinary DNS, where the
#: answer describes some other host entirely and says nothing about the sender.
MDNS_PORT = 5353

#: Where a name is recorded as having come from.
SOURCE_MDNS = "mDNS announcement"

#: Service labels an instance name is wrapped in - ``_companion-link._tcp``,
#: ``_googlecast._tcp`` and so on. The device's own name is what precedes them.
_SERVICE_LABEL = re.compile(r"\._[A-Za-z0-9-]+\._(?:tcp|udp)\b")

#: The trailing mDNS zone.
_LOCAL_SUFFIX = re.compile(r"\.local\.?$", re.IGNORECASE)

#: A name worth recording. Letters, digits, spaces, hyphens, underscores and
#: apostrophes - what device names actually contain: "Ivandoe",
#: "DESKTOP-VKRMBR2", "kristian-VMware-Virtual-Platform", "Mark's iPhone",
#: and "Android_WTKS0CKK", which Android builds from the model and serial.
#:
#: The underscore is here because leaving it out silently refused every
#: Android on this network - the rule looked strict and was simply wrong.
_PLAUSIBLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 '_\-]{0,62}$")

#: A machine-generated identifier, not a name anyone chose. Google Nearby
#: publishes these on this network - "nearby-presence-nsd-57469620-8721-4106-
#: 8e9d-3294c145da98" - and regenerates them, so storing one would put a value
#: in the inventory that changes on its own and identifies nothing.
#:
#: The SRV *target* should never carry such a label; this is a second line of
#: defence for a device that sets its target to one anyway.
_UUID_LIKE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

#: Names that identify a protocol or a role rather than a device. A host
#: answering for one of these is advertising a service, not naming itself.
_NOT_A_DEVICE = frozenset(
    {
        "wpad", "localhost", "lb", "_services", "_tcp", "_udp", "local",
        "in-addr", "arpa", "ip6",
    }
)


def announced_hostname(packet: CapturedPacket) -> str:
    """The name a device published about itself in this frame, or ``""``.

    Returns the bare device name - ``Ivandoe``, not
    ``Ivandoe._companion-link._tcp.local`` - so it can be stored beside a name
    that came from DNS and read the same way.
    """
    if packet.dns_response is not True:
        # A query says what the sender wants, not what it is called.
        return ""
    if MDNS_PORT not in (packet.src_port, packet.dst_port):
        return ""
    if not packet.src_ip:
        return ""
    # TShark emits a comma-separated list when a frame carries several SRV
    # records. They name the same host in every announcement seen here, and
    # taking the first keeps one frame from yielding two identities.
    for raw in str(packet.dns_srv_target or "").split(","):
        name = _device_name(raw)
        if name:
            return name
    return ""


def _device_name(record_name: str) -> str:
    """Strip an mDNS record name down to the device name, if there is one."""
    text = str(record_name or "").strip()
    if not text:
        return ""
    # An SRV target is already a host name - "akii.local" - so only the zone
    # is stripped. The service-label rule stays as a guard: a malformed or
    # unusual target that still carries them is reduced rather than trusted.
    text = _SERVICE_LABEL.sub("", text)
    text = _LOCAL_SUFFIX.sub("", text).strip()
    if not text or "." in text:
        # A dot left over means this was never a single-label device name -
        # a reverse-lookup zone, say, or a name from some other domain.
        return ""
    if text.lower() in _NOT_A_DEVICE or text.startswith("_"):
        return ""
    if _UUID_LIKE.search(text):
        return ""
    if not _PLAUSIBLE.match(text):
        return ""
    return text
