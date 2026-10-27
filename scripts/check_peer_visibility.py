"""Answer one question: does this capture point receive another device's traffic?

Run it on the monitoring laptop (Device A) while another authorised device
(Device B) browses normally. It captures on the selected interface, classifies
every frame by who it belongs to, and reports a verdict.

    python scripts/check_peer_visibility.py
    python scripts/check_peer_visibility.py --seconds 60 --peer 172.20.10.3

Why it exists: "AETHRA-SEC does not show the other device" has two causes with
opposite remedies. Either the packets arrive and this application discards them
- a bug - or they never arrive, which no change to this application can fix.
Only a capture can tell them apart, and guessing wrongly wastes a lot of time.

What it does NOT do: it does not put the adapter in monitor mode, inject
frames, deauthenticate anyone, or attempt to read traffic the network has not
delivered. It observes the selected interface exactly as the application does,
and reports what arrived.

Exit status is 0 when peer traffic was observed, 1 when it was not, so it can
be used as a check. "Not observed" is a legitimate finding, not a failure of
this script.
"""

from __future__ import annotations

import argparse
import collections
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aethra_sec.integrations.pyshark_capture.interfaces import (  # noqa: E402
    find_tshark,
    list_capture_interfaces,
)
from aethra_sec.services.capture_diagnostic import (  # noqa: E402
    VISIBILITY_LIMITATION,
    WIRELESS_NOTE,
    _is_wireless,
)

RULE = "=" * 74


def _banner(text: str) -> None:
    print(f"\n{RULE}\n {text}\n{RULE}")


def _is_group_mac(mac: str) -> bool:
    """True for broadcast and multicast destinations.

    Bit 0 of the first octet marks a group address. These are flooded to every
    station by design, so seeing them says nothing about peer visibility - and
    counting them as peer traffic would turn a negative result into a false
    positive.
    """
    cleaned = (mac or "").strip().lower()
    if not cleaned:
        return False
    if cleaned.startswith("ff:ff"):
        return True
    try:
        return bool(int(cleaned.split(":")[0], 16) & 0x01)
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=45, help="capture duration")
    parser.add_argument("--interface", default="", help="capture device name")
    parser.add_argument("--peer", default="", help="Device B's address, if known")
    arguments = parser.parse_args(argv)

    tshark = find_tshark()
    if not tshark:
        print("TShark was not found. Install Wireshark, or set AETHRA_TSHARK_PATH.")
        return 2

    interfaces = list_capture_interfaces()
    if arguments.interface:
        chosen = next(
            (i for i in interfaces if i.name == arguments.interface), None
        )
        if chosen is None:
            print(f"No such interface: {arguments.interface}")
            return 2
    else:
        chosen = next(
            (i for i in interfaces if getattr(i, "is_primary", False)),
            interfaces[0] if interfaces else None,
        )
    if chosen is None:
        print("No capture interfaces were found.")
        return 2

    me = getattr(chosen, "primary_ipv4", "") or ""
    _banner("PEER VISIBILITY CHECK")
    print(f"\n  Interface   : {chosen.display_name}")
    print(f"  Device      : {chosen.name}")
    print(f"  Local IPv4  : {me or 'unknown'}")
    print(f"  Duration    : {arguments.seconds}s")
    if arguments.peer:
        print(f"  Looking for : {arguments.peer}")
    print("\n  Browse normally on Device B now.\n")

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            str(tshark), "-i", chosen.name, "-p",
            "-a", f"duration:{arguments.seconds}",
            "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
            "-e", "eth.dst", "-e", "_ws.col.protocol",
            "-E", "occurrence=f",
        ],
        capture_output=True, text=True,
    )
    if completed.returncode != 0 and not completed.stdout:
        print("  Capture failed:")
        print("   ", (completed.stderr or "").strip().splitlines()[-1:] or "unknown")
        print("\n  On Windows this usually means AETHRA-SEC must run as "
              "Administrator, with Npcap installed.")
        return 2

    own = peer = group = other = 0
    flows: collections.Counter = collections.Counter()
    for line in completed.stdout.splitlines():
        parts = (line + "\t\t\t").split("\t")
        source, destination, eth_dst = parts[0], parts[1], parts[2]
        if not source and not destination:
            other += 1
            continue
        if me and (source == me or destination == me):
            own += 1
            continue
        if _is_group_mac(eth_dst):
            group += 1
            continue
        peer += 1
        flows[(source, destination, parts[3])] += 1

    total = own + peer + group + other
    _banner("RESULT")
    print(f"\n  total frames                  : {total:,}")
    print(f"  this host's own traffic       : {own:,}")
    print(f"  broadcast / multicast         : {group:,}")
    print(f"  non-IP (ARP and similar)      : {other:,}")
    print(f"  PEER UNICAST (another device) : {peer:,}")

    if peer:
        print("\n  Peer traffic IS delivered to this interface.")
        print("  AETHRA-SEC can monitor it. Top flows observed:\n")
        for (source, destination, protocol), count in flows.most_common(10):
            print(f"    {source:>15} -> {destination:<15} {protocol:<10} {count}")
        return 0

    _banner("TRAFFIC IS NOT VISIBLE TO THIS MONITORING ENDPOINT")
    print(f"\n  {VISIBILITY_LIMITATION}\n")
    if _is_wireless(chosen.description, chosen.name):
        print(f"  {WIRELESS_NOTE}\n")
    print("  This is not a fault in AETHRA-SEC, and it is not fixed by any")
    print("  setting inside it. The capture point has to be moved to somewhere")
    print("  the traffic actually passes through.\n")
    if arguments.peer:
        print(f"  Nothing from {arguments.peer} reached this adapter during the run.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
