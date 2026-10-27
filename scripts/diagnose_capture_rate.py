"""Compare what crossed the interface with what AETHRA-SEC measured.

Run this WHILE an attack is in progress. It answers one question: when the
IDS Alerts table reports a rate, is that the rate on the wire, or only the
part of it that reached the analysis?

Three independent sources are sampled over the same seconds:

    1. The operating system's own per-adapter packet counters. Npcap is not
       in the path of these, so they are the ground truth for what the
       adapter received.
    2. TShark reading the same interface directly, counted per protocol.
    3. AETHRA-SEC's own capture statistics, if the console is running.

A large gap between (1) and (3) means the measured rate - and therefore the
severity - is based on a fraction of the traffic. That is a capture problem,
not a classification problem, and no threshold change will fix it.

Nothing is sent, nothing is attacked, and no file is modified. This only
reads counters.

    python scripts/diagnose_capture_rate.py [seconds] [--interface NAME]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("seconds", nargs="?", type=int, default=15)
    parser.add_argument("--interface", default=None,
                        help="adapter friendly name, e.g. \"Wi-Fi\"")
    return parser.parse_args()


def _tshark_path() -> str | None:
    for candidate in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return None


def main() -> int:
    args = parse_args()
    import psutil

    counters = psutil.net_io_counters(pernic=True)
    name = args.interface
    if name is None:
        # The busiest adapter over a short sample is the one being attacked.
        first = {k: v.packets_recv + v.packets_sent for k, v in counters.items()}
        time.sleep(1.5)
        second = psutil.net_io_counters(pernic=True)
        deltas = {
            k: (second[k].packets_recv + second[k].packets_sent) - v
            for k, v in first.items() if k in second
        }
        name = max(deltas, key=deltas.get)
        print(f"  busiest adapter over 1.5s: {name} "
              f"({deltas[name]} packets)\n")
    if name not in counters:
        print(f"  no such adapter: {name}")
        print(f"  available: {', '.join(sorted(counters))}")
        return 2

    # --- TShark on the same interface, in parallel -----------------------
    tshark = _tshark_path()
    proc = None
    if tshark:
        proc = subprocess.Popen(
            [tshark, "-i", name, "-a", f"duration:{args.seconds}", "-Q",
             "-z", "io,stat,0,COUNT(icmp)icmp,COUNT(udp)udp,COUNT(tcp)tcp"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    else:
        print("  TShark not found; the adapter counters are still measured.\n")

    start = psutil.net_io_counters(pernic=True)[name]
    t0 = time.monotonic()
    print(f"  sampling '{name}' for {args.seconds}s - start the attack now "
          f"if it is not already running\n")
    time.sleep(args.seconds)
    end = psutil.net_io_counters(pernic=True)[name]
    elapsed = time.monotonic() - t0

    os_packets = ((end.packets_recv - start.packets_recv)
                  + (end.packets_sent - start.packets_sent))
    os_rate = os_packets / elapsed

    print("  ADAPTER (operating system counters - ground truth)")
    print(f"    packets over {elapsed:.1f}s : {os_packets:,}")
    print(f"    rate                 : {os_rate:,.1f} packets/second\n")

    if proc is not None:
        out, _ = proc.communicate(timeout=args.seconds + 30)
        totals = {}
        for key in ("icmp", "udp", "tcp"):
            m = re.search(rf"COUNT\({key}\)", out)
            totals[key] = m is not None
        numbers = re.findall(r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", out)
        print("  TSHARK (same interface, independent of AETHRA-SEC)")
        if numbers:
            icmp, udp, tcp = (int(x) for x in numbers[-1])
            total = icmp + udp + tcp
            print(f"    ICMP {icmp:,}   UDP {udp:,}   TCP {tcp:,}")
            print(f"    combined rate        : {total/elapsed:,.1f} pkt/s")
        else:
            print("    (no counts returned; the interface may need "
                  "Administrator rights)")
        print()

    # --- what AETHRA-SEC itself measured ---------------------------------
    print("  AETHRA-SEC")
    try:
        import logging

        logging.disable(logging.INFO)
        from aethra_sec.core.application import ApplicationContext

        context = ApplicationContext()
        context.start()
        rows = context.db.query(
            "SELECT rule_id, src_ip, severity, peak_severity, "
            "observed_value, latest_value, window_seconds, event_count "
            "FROM traffic_anomalies WHERE last_seen >= NOW() - INTERVAL 2 "
            "MINUTE ORDER BY id DESC LIMIT 6"
        )
        if not rows:
            print("    no flood detections in the last two minutes")
        for r in rows:
            print(f"    {r['rule_id']:18s} from {r['src_ip']:<15s} "
                  f"peak {float(r['observed_value']):>8,.1f} pps  "
                  f"current={r['severity']} peak={r['peak_severity']}")
        context.shutdown("capture diagnosis")
    except Exception as exc:  # noqa: BLE001
        print(f"    could not read the database: {exc}")

    print()
    print("  HOW TO READ THIS")
    print("    If the adapter rate is far above what AETHRA-SEC measured per")
    print("    source, the capture is losing traffic and the severity is")
    print("    being decided on a fraction of the attack. Capture on a wired")
    print("    interface, or run elevated, and measure again.")
    print("    Remember the adapter total counts BOTH directions of a ping,")
    print("    while a flood rule counts one source - so a reply-generating")
    print("    attack shows about twice the per-source rate here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
