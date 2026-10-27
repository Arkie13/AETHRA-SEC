"""What the capture point can actually see, stated from evidence.

Three different questions get confused constantly, and keeping them apart is
the whole point of this module:

**Network visibility** - whether the packets ever arrive at the capture
interface. This is a property of where the sensor is plugged in, not of the
software. A switch forwards a unicast frame only towards its destination, so
an ordinary switched port receives this host's own traffic plus broadcast and
multicast, and nothing else. No capture library changes that; Wireshark on the
same port sees exactly as much and exactly as little.

**Packet capture** - whether Npcap/TShark can read the frames that do arrive.

**Application-content visibility** - whether the payload is readable. TLS
payload is not, whatever the capture point is.

This module answers only the first. It derives a state from frames the sensor
genuinely captured, through :class:`~aethra_sec.analytics.peer_visibility.
VisibilityReport`, and never from the operator having selected an interface.
Selecting a monitoring interface is an intention; receiving a frame whose
source and destination are both other machines is evidence. Only the second
is allowed to produce a claim of network-wide visibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

#: Peer unicast frames needed before transit traffic is called observed.
#: Imported from the tracker so there is one definition of "enough evidence".
from aethra_sec.analytics.peer_visibility import VISIBILITY_THRESHOLD

#: Frames that must be captured before the sensor will say anything at all.
#: Below this the honest answer is UNKNOWN: an interface that has just started
#: has not had the chance to receive peer traffic, and reporting LOCAL_ONLY
#: then would be a conclusion drawn from no data.
MINIMUM_FRAMES_FOR_A_VERDICT = 200


class CaptureVisibility(str, Enum):
    """How much of the network this capture point can see."""

    #: Npcap/TShark cannot capture on this interface at all.
    CAPTURE_UNAVAILABLE = "CAPTURE_UNAVAILABLE"
    #: Too few frames so far to draw any conclusion.
    UNKNOWN = "UNKNOWN"
    #: Only this host's own traffic, plus broadcast and multicast.
    LOCAL_ONLY = "LOCAL_ONLY"
    #: The operator has declared this interface a mirror/SPAN destination, but
    #: no transit frame has arrived yet to corroborate it.
    MIRRORED_TRAFFIC = "MIRRORED_TRAFFIC"
    #: Real frames observed whose source and destination are both other hosts.
    TRANSIT_OBSERVED = "TRANSIT_OBSERVED"

    @property
    def label(self) -> str:
        """Short wording for the interface."""
        return {
            CaptureVisibility.CAPTURE_UNAVAILABLE: "CAPTURE UNAVAILABLE",
            CaptureVisibility.UNKNOWN: "UNKNOWN",
            CaptureVisibility.LOCAL_ONLY: "LOCAL ONLY",
            CaptureVisibility.MIRRORED_TRAFFIC: "MONITORING INTERFACE SELECTED",
            CaptureVisibility.TRANSIT_OBSERVED: "TRANSIT TRAFFIC OBSERVED",
        }[self]

    @property
    def sees_other_hosts(self) -> bool:
        """True only where real third-party traffic has been captured.

        Deliberately false for :attr:`MIRRORED_TRAFFIC`: a declared monitoring
        role is a statement of intent by the operator, and the sensor must not
        turn that into a claim about what it can see.
        """
        return self is CaptureVisibility.TRANSIT_OBSERVED


@dataclass(frozen=True)
class VisibilityState:
    """A derived state, with the evidence that produced it."""

    state: CaptureVisibility
    #: One sentence an operator can act on. Never speculative.
    detail: str
    frames: int = 0
    peer_frames: int = 0
    peer_hosts: int = 0
    #: Devices seen only via broadcast - present, but not observable.
    silent_peers: int = 0
    #: Whether an operator declared this interface a mirror destination.
    monitoring_declared: bool = False

    @property
    def transit_observed(self) -> bool:
        """Whether real third-party traffic has been captured."""
        return self.state is CaptureVisibility.TRANSIT_OBSERVED

    @property
    def transit_text(self) -> str:
        """``OBSERVED`` / ``NOT OBSERVED``, for the health screen."""
        return "OBSERVED" if self.transit_observed else "NOT OBSERVED"


def derive(
    report: Any,
    *,
    capture_available: bool = True,
    monitoring_declared: bool = False,
) -> VisibilityState:
    """Decide what this capture point can see, from captured frames only.

    Args:
        report: a :class:`~aethra_sec.analytics.peer_visibility.VisibilityReport`
            (or anything exposing the same counters).
        capture_available: whether Npcap/TShark can capture here at all.
        monitoring_declared: whether an operator has recorded that this
            interface is wired to a mirror/SPAN destination. This can raise
            UNKNOWN to MIRRORED_TRAFFIC - which only means "selected for
            monitoring" - and can never, by itself, produce TRANSIT_OBSERVED.
    """
    if not capture_available:
        return VisibilityState(
            state=CaptureVisibility.CAPTURE_UNAVAILABLE,
            detail=(
                "Packet capture is unavailable on this interface, so nothing "
                "can be observed. Check that Npcap is installed and that "
                "AETHRA-SEC is running with the privileges capture requires."
            ),
            monitoring_declared=monitoring_declared,
        )

    frames = int(getattr(report, "frames", 0) or 0)
    peer_frames = int(getattr(report, "peer_frames", 0) or 0)
    peer_hosts = int(getattr(report, "peer_hosts", 0) or 0)
    silent = int(getattr(report, "group_only_hosts", 0) or 0)

    common = {
        "frames": frames,
        "peer_frames": peer_frames,
        "peer_hosts": peer_hosts,
        "silent_peers": silent,
        "monitoring_declared": monitoring_declared,
    }

    # Evidence outranks everything: frames whose source and destination are
    # both other machines can only have arrived because the network delivered
    # a copy here.
    if peer_frames >= VISIBILITY_THRESHOLD:
        return VisibilityState(
            state=CaptureVisibility.TRANSIT_OBSERVED,
            detail=(
                f"Transit traffic observed: {peer_frames:,} frame(s) between "
                f"{peer_hosts} other device(s), where neither endpoint is this "
                "host. Traffic between other machines on the monitored segment "
                "is reaching this interface."
            ),
            **common,
        )

    if frames < MINIMUM_FRAMES_FOR_A_VERDICT:
        return VisibilityState(
            state=(
                CaptureVisibility.MIRRORED_TRAFFIC
                if monitoring_declared
                else CaptureVisibility.UNKNOWN
            ),
            detail=(
                f"Only {frames:,} frame(s) captured so far - too few to judge "
                "what this interface can see. "
                + (
                    "The interface is configured as a monitoring destination; "
                    "transit traffic has not been observed yet."
                    if monitoring_declared
                    else "Let the capture run, then check again."
                )
            ),
            **common,
        )

    # Enough frames, and none of them between two other hosts.
    if silent:
        detail = (
            f"Local traffic only. {silent} other device(s) are demonstrably on "
            "this network - their broadcast traffic arrives here - but none of "
            "their unicast traffic is delivered to this interface. That is the "
            "switch forwarding frames only towards their destination, not a "
            "capture fault. A mirror/SPAN destination port or a network TAP is "
            "what makes that traffic observable."
        )
    else:
        detail = (
            "Local traffic only: every captured frame has this host as one of "
            "its endpoints, or is broadcast/multicast. No traffic between "
            "other devices has reached this interface."
        )
    if monitoring_declared:
        detail += (
            " This interface is configured as a monitoring destination, so "
            "verify the mirror session on the switch - it may not be "
            "forwarding, or may be mirroring a different port."
        )

    return VisibilityState(
        state=(
            CaptureVisibility.MIRRORED_TRAFFIC
            if monitoring_declared
            else CaptureVisibility.LOCAL_ONLY
        ),
        detail=detail,
        **common,
    )


#: Shown where an operator asks why other devices' traffic is missing. States
#: the limitation in terms that are true of any capture tool, so nobody reads
#: it as an AETHRA-SEC defect.
WHY_TRANSIT_IS_MISSING = (
    "A switch forwards a unicast frame only towards the port its destination "
    "lives on. An ordinary switched port therefore receives this host's own "
    "traffic plus broadcast and multicast, and nothing else. Promiscuous mode "
    "does not change that: it stops the adapter discarding frames it was "
    "given, and the switch was never going to give it these. Wireshark at the "
    "same point sees exactly the same traffic, and with a mirror/SPAN "
    "destination port or a network TAP both see the mirrored traffic."
)
