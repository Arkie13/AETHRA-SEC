# AETHRA-SEC — Port-Scan Detection and Network Visibility Audit

**Date:** 6 October 2026
**Scope:** packet capture, Snort IDS integration, alert pipeline, port-scan
detection, and the network-visibility limitation that governs all of it.
**Installation audited:** the live one — Wi-Fi `192.168.100.31/24`, MariaDB
10.4.32, 311 Snort alerts and 2,010 traffic anomalies on record.

Every measurement below was taken on that installation. Where something could
not be executed, it says so and is not marked PASS.

---

## 0. Three questions that must not be merged

The whole audit turns on keeping these apart:

| | Question | Decided by |
|---|---|---|
| **Network visibility** | Do the packets reach the capture interface at all? | Where the sensor is plugged in |
| **Packet capture** | Can Npcap/TShark read the frames that do arrive? | Driver and privileges |
| **IDS detection** | Does a rule match the frames that were read? | Snort config, `HOME_NET`, rules |
| **Application content** | Is the payload readable? | Encryption — **not** the capture point |

A failure in the first cannot be fixed by improving the second or third, and
no amount of any of them makes TLS payload readable.

---

## 1. Existing architecture, traced at runtime

Not inferred from filenames. This is what the running processes do:

```
   Windows side                                   WSL (Ubuntu-22.04)
   ────────────                                   ──────────────────
   tshark ring buffer                             snort_pcap_pipeline.sh
     -b duration:10 -b files:30                     polls for completed chunks
     -w C:\Snort-wsl\capture\cap.pcap   ────────►   snort -c <conf> -r <chunk> -q
          │                                               │
          │ (separate, AETHRA's own)                      ▼
          ▼                                        appends alert_fast lines to
   PyShark / dumpcap on the Wi-Fi NPF device       C:\Snort-wsl\log\alert
          │                                               │
          ▼                                               ▼
   PacketCaptureService ──► PacketView ──►         SnortService (transport=file)
          │                   ├─ AnomalyRuleEngine   tails that file
          │                   └─ PeerVisibilityTracker      │
          ▼                                                 ▼
   traffic_anomalies                                parser.parse_fast
   (AETHRA's own rules)                                     │
                                                            ▼
                                                     snort_alerts (MariaDB)
                                                            │
                                    ┌───────────────────────┼───────────────┐
                                    ▼                       ▼               ▼
                              IDS Alerts UI          Dashboard count   Notification
                                    │
                                    ▼
                            Mitigation mapping
```

**Facts worth stating plainly, because they are easy to assume wrongly:**

* **AETHRA-SEC does not launch Snort.** `snort_service.py` contains no process
  spawn for it. Snort is started by an external WSL script, and AETHRA-SEC is
  purely a consumer of the alert file. Stopping AETHRA-SEC does not stop Snort.
* **Snort does not capture live.** It runs in `-r` read mode over 10-second
  pcap chunks that a Windows-side tshark ring buffer produces. This decouples
  Snort from WSL2's own network namespace — and it means **Snort sees exactly
  what that tshark captured, no more and no less.** The capture point is
  therefore the single thing that determines what the IDS can ever detect.
* **There are two independent detectors**, and they are often confused:
  * `AnomalyRuleEngine` — AETHRA's own rules, writing to `traffic_anomalies`
    (`RULE-PORT-SCAN`, `RULE-TCP-SYN-RATE`, …);
  * **Snort** — writing to `snort_alerts`.
  The IDS Alerts screen shows the second. The first is traffic analytics.

### Verified live

The pipeline is real and currently working. Snort wrote at 21:49 local:

```
10/06-21:49:01.887690  [**] [1:1000002:2] TCP SYN (any port) [**] ... {TCP}
192.168.100.254:58737 -> 192.168.100.31:7070
```

and AETHRA persisted it as `snort_alerts` #310 at 13:49:03 UTC. Same event,
same addresses, correct timezone offset.

---

## 2. Root cause — why scans between other hosts were not detected

There were **three** independent blockers. Fixing any one alone detects
nothing; this is the central finding of the audit.

### Blocker 1 — Visibility (physical)

A switch forwards a unicast frame only towards the port its destination lives
on. An ordinary switched port therefore receives this host's own traffic plus
broadcast and multicast, and nothing else.

Promiscuous mode does **not** change this. It stops the adapter discarding
frames it was handed; the switch was never going to hand it these.

**Measured, this installation, 120 s on the ordinary Wi-Fi port:**

```
packets captured  : 3,987        capture drops : 0
  involving this host : 3,835
  broadcast/multicast :   152
  between two other devices : 0
other devices demonstrably present (their broadcast arrives) : 20
```

Twenty other devices are provably on the segment, and **not one frame** of
their unicast traffic was delivered here. That is the network declining to
deliver it, not a capture fault.

### Blocker 2 — `HOME_NET` is a single host

```
C:\Snort-wsl\home_net.conf:   ipvar HOME_NET 192.168.100.31/32
```

and every rule in `local.rules` is `-> $HOME_NET`. So even with perfect
mirroring, a scan from `192.168.100.10` to `192.168.100.222` matches **no
rule**, because the destination is not in `HOME_NET`.

This is not a defect in isolation — it is the correct scoping for an endpoint
sensor, and it is deliberately why this host's own outbound browsing is not
reported as an attack on itself. It simply cannot also serve network
monitoring.

### Blocker 3 — No port-scan signature existed

`local.rules` held SIDs 1000001–1000010: ICMP echo, TCP SYN, DNS, HTTP/HTTPS
SYN, and four flood rules. **No port-scan rule, and no `sfportscan`.**

A Snort *rule* cannot express the port-scan question: `threshold` counts
matching events, not distinct destination ports, so a threshold rule on SYNs
is a SYN-rate rule — which sid 1000007 already was.

---

## 3. Defects found and fixed

### 3.1 Port-scan alerts were silently discarded by the parser *(critical)*

`sfportscan` reports its pseudo-packet as `{PROTO:255}`. The protocol group in
the `alert_fast` regex was `[A-Za-z0-9_-]+` — **no colon**, so the group
failed, the whole line failed to match, and `parse_fast` returned `None`.

Had the preprocessor simply been enabled, every port-scan alert would have
been dropped before reaching the database, with no error and no record.

Fixed by admitting the colon. Verified against four portscan variants:

```
gid=122  sid=1   192.168.100.10 -> 192.168.100.222  (portscan) TCP Portscan
gid=122  sid=3   192.168.100.10 -> 192.168.100.222  (portscan) TCP Portsweep
gid=122  sid=5   10.0.0.5       -> 10.0.0.9         (portscan) TCP Filtered Portscan
gid=122  sid=17  10.0.0.5       -> 10.0.0.9         (portscan) UDP Portscan
```

Both endpoints survive as the *other* hosts — Part 6's requirement that
AETHRA-SEC never substitutes itself for a real source or destination.

### 3.2 `RULE-PORT-SCAN` counted replies as scanning *(high)*

AETHRA's own rule ran on **every** TCP/UDP packet. The SYN-flood rule beside
it correctly guards on `packet.is_syn_only`; the port-scan rule had no
equivalent gate, so established-session traffic counted.

A server answering 20 of this host's outbound connections lands on 20 distinct
ephemeral ports, which is indistinguishable from one source touching 20 ports:

```
192.168.100.202 contacted 20 distinct destination port(s) on 192.168.100.31
ports: 53419, 53420, 53421, … 53438
```

**Measured across all 173 inbound detections on this installation:**

| | |
|---|---|
| Touching any well-known service port | **0 of 173** |
| Hitting only client-side ports | **173 of 173** |
| Median share of consecutive port numbers | **95%** |

Every inbound "port scan" on record was reply traffic. By contrast the
**outbound** detections — this host's own authorised Nmap assessments — were
correct throughout: **133 of 151** touched well-known service ports, with only
5–16% consecutive. The rule's logic was sound; its input was wrong.

Fixed with a connection-attempt gate: TCP must be SYN-without-ACK (exact);
UDP must target a port below 49152, since a reply arrives at the ephemeral
port the client chose. The UDP half is an approximation and is documented as
one in the code — a UDP scan confined to ports above 49152 is not counted.

**Measured after the fix**, over the negative-test window:

```
port-scan detections raised : 2
  INBOUND  : 0        (the false-positive class)
  OUTBOUND : 2        (real Nmap assessments, service-port signatures intact)
```

Both new detections show classic scan signatures
(`21, 22, 23, 110, 143, 443, 445, …`), so genuine detection is unaffected.

### 3.3 Fragile capture-interface identifier *(medium, not fixed — operator-owned)*

The tshark ring buffer feeding Snort is launched as:

```
tshark -i 2 -w C:\Snort-wsl\capture\cap.pcap -b duration:10 -b files:30
```

`-i 2` is a **positional index** into `tshark -D`, and that ordering is not
stable. On this machine *now*, index 2 is `Local Area Connection* 11`; the
running dumpcap child has the Wi-Fi device pinned explicitly, so the index
resolved differently when it was launched.

Not changed here because the script is outside this repository, but it must be
pinned to the NPF device GUID before the monitoring NIC is relied on. See §9.

---

## 4. Capture visibility states

New module: `aethra_sec/analytics/capture_visibility.py`, deriving state from
frames actually captured through the existing `PeerVisibilityTracker`.

| State | Meaning | Claims to see other hosts |
|---|---|---|
| `CAPTURE_UNAVAILABLE` | Npcap/TShark cannot capture here | No |
| `UNKNOWN` | Fewer than 200 frames — nothing measured yet | No |
| `LOCAL_ONLY` | Only this host's traffic, plus broadcast/multicast | No |
| `MIRRORED_TRAFFIC` | Operator declared a monitoring role; **no transit frame yet** | **No** |
| `TRANSIT_OBSERVED` | Real frames seen where neither endpoint is this host | **Yes** |

**The decisive property, held by a parametrised test:** declaring a monitoring
role can *never* produce `TRANSIT_OBSERVED`, at any frame count. Selecting an
interface is an intention; receiving a third-party frame is evidence, and only
evidence is allowed to produce a visibility claim. `MIRRORED_TRAFFIC` is
labelled **"MONITORING INTERFACE SELECTED"** — never "SPAN CONFIGURED".

Wired into `SubsystemProbes.capture_visibility` → `HealthService._probe_capture`,
so the health screen reports capture state and visibility as two separate
facts. A running sensor on an ordinary port now reads:

```
Capture:      CAPTURING
Visibility:   LOCAL ONLY
Transit:      NOT OBSERVED
```

---

## 5. Port-scan detection architecture

### Snort (network-wide, GID 122)

`sfportscan` is the only mechanism that answers "many **distinct** ports from
one source", so it is what detects scanning. Added to `snort.wsl.conf` with
`watch_ip { $HOME_NET }`, which keeps the existing single-host scope: scans
**aimed at** the protected host.

For scans **between two other hosts**, a separate `snort.monitor.conf` widens
`HOME_NET` to the monitored segment via its own
`home_net.monitor.conf` — deliberately a different file from `home_net.conf`,
which a Windows-side updater rewrites with this host's `/32`. Pointing both at
one file would have the updater silently narrow monitoring mode back to a
single host.

The two configs are kept separate because widening `HOME_NET` in the endpoint
config would also widen the broad single-packet rules (1000001–1000005) to
every pair of hosts on the segment — reintroducing exactly the false positives
those rules were narrowed to avoid.

`ignore_scanners` is deliberately **not** set: this host's own authorised Nmap
assessments are real port scans and are reported as such. A sensor that hides
scans from one address cannot report that address being misused.

### AETHRA's own rule (`RULE-PORT-SCAN`)

Unchanged in intent — 20 distinct destination ports in 10 seconds, keyed on
`(source, destination)` and therefore direction-agnostic — now gated on
connection attempts per §3.2.

---

## 6. HTTPS and application content

Mirrored traffic makes **metadata** observable: source and destination
addresses, ports, protocol, DNS names where unencrypted, TLS SNI where
present, HTTP metadata for plain HTTP, packet sizes and timing.

**TLS payload remains encrypted.** AETHRA-SEC cannot read another user's
HTTPS search terms, page content, credentials or cookies, and no TLS
interception is implemented or planned here. Capturing a packet and reading
its contents are different capabilities, and only the first is affected by the
capture point.

---

## 7. Test results

### Negative test — ordinary switched port, no SPAN *(REQUIRED, EXECUTED, PASS)*

120 s on Wi-Fi `192.168.100.31`, no mirror session:

```
packets captured 3,987   drops 0   queue depth 0
  own/local 3,835   broadcast/mcast 152   peer unicast 0
  other devices present but unobservable: 20

visibility       : LOCAL_ONLY ("LOCAL ONLY")
transit traffic  : NOT OBSERVED
sees other hosts : False

snort_alerts     311 -> 311   (+0)   <- nothing fabricated
```

| Assertion | Result |
|---|---|
| Visibility is not `TRANSIT_OBSERVED` | **PASS** |
| Transit reads NOT OBSERVED | **PASS** |
| Does not claim to see other hosts | **PASS** |
| No port-scan alert invented | **PASS** |

### Positive test — SPAN enabled *(NOT EXECUTED — HARDWARE DEPENDENCY)*

**NOT EXECUTED — HARDWARE/NETWORK DEPENDENCY.** This machine has no managed
switch with a mirror session and no second NIC wired to a SPAN destination
port. The procedure is in §9; running it is the remaining work.

Not marked PASS. Not simulated. No alert was manufactured to stand in for it.

### Snort configuration validation *(NOT EXECUTED — TOOL DEPENDENCY)*

**NOT EXECUTED — TOOL DEPENDENCY.** `wsl -e snort -V` reports
`execvpe(snort) failed: No such file or directory` — the Snort binary is not
present in the WSL distribution on this machine, so `snort -T -c <conf>` could
not be run. The configs are written to Snort 2.9 syntax matching the existing
file, and the `sfportscan` line follows the documented form, but **they have
not been machine-validated.** Validate with `snort -T` before relying on them.

### Automated tests

| Run | Result |
|---|---|
| Baseline, before changes | **2,713 passed** |
| `tests/test_network_visibility_port_scan.py` (new, 29 tests) | **29 passed** |
| Full suite, after changes | **2,742 passed, 0 failed** |

---

## 8. Files changed

| File | Change |
|---|---|
| `aethra_sec/analytics/capture_visibility.py` | **new** — visibility states derived from captured frames |
| `aethra_sec/integrations/snort/parser.py` | protocol group admits `PROTO:255`, so GID 122 port-scan alerts are no longer silently dropped |
| `aethra_sec/analytics/anomaly_rules.py` | `_initiates()` gate — the port-scan rule counts connection attempts, not replies |
| `aethra_sec/services/health_service.py` | `capture_visibility` probe; capture status now reports visibility and transit separately |
| `aethra_sec/core/application.py` | wires the live `PeerVisibilityTracker` into the health probes |
| `deploy/snort/snort.wsl.conf` | `sfportscan` added, scoped to `$HOME_NET` |
| `deploy/snort/snort.monitor.conf` | **new** — monitoring-mode config for a mirrored capture point |
| `deploy/snort/home_net.monitor.conf.example` | **new** — segment-scoped `HOME_NET` template |
| `tests/test_network_visibility_port_scan.py` | **new** — 29 regression tests |

No database migration was required. No historical alert was altered or
deleted. No index was added — see §10.

---

## 9. Wiring the monitoring NIC to a SPAN destination

Do this on the switch and the host; AETHRA-SEC configures only its own side
and never reconfigures a switch.

1. **Second NIC.** Fit a second adapter. It needs **no IP address** — a SPAN
   destination port is receive-only. Do not make it the default route and do
   not change the routing table; the management NIC keeps all normal
   connectivity, the database included.
2. **Switch.** On the managed switch, create a monitor session whose *source*
   is the port(s) carrying the traffic of interest (or the lab VLAN) and whose
   *destination* is the port the monitoring NIC is plugged into. Mirror **both
   directions**; one direction halves what the IDS can reconstruct.
3. **Confirm frames arrive**, before touching AETHRA-SEC:
   ```
   tshark -D                     # note the monitoring NIC's \Device\NPF_{GUID}
   tshark -i \Device\NPF_{GUID} -c 50
   ```
   You should see frames whose source and destination are both *other* hosts.
   If not, the mirror session is wrong — stop here; nothing downstream can
   compensate.
4. **Repoint the capture that feeds Snort** to that device, **by GUID, not by
   index** (see §3.3):
   ```
   tshark -i \Device\NPF_{GUID} -w C:\Snort-wsl\capture\cap.pcap -b duration:10 -b files:30
   ```
5. **Set the monitored range.** Copy `deploy/snort/home_net.monitor.conf.example`
   to `C:\Snort-wsl\home_net.monitor.conf` and set `ipvar HOME_NET` to the
   authorised laboratory range, and only that range.
6. **Point the Snort pipeline at the monitoring config** —
   `CONF=/mnt/.../deploy/snort/snort.monitor.conf` — and validate first with
   `snort -T -c <conf>`.
7. **Select the monitoring interface in AETHRA-SEC** and start capture.
   Visibility will read `MONITORING INTERFACE SELECTED` until a real
   third-party frame arrives, then `TRANSIT TRAFFIC OBSERVED`. If it stays on
   the former, the mirror is not delivering — the application will say so
   rather than claim network-wide visibility.
8. **Run the authorised scan** from the attacker host against the target host,
   both inside the authorised range, and confirm the alert reaches the IDS
   Alerts screen with the two *other* hosts as source and destination.

**Note the configuration-ownership split:** the Snort instance currently
feeding this installation reads
`C:\xampp\htdocs\AETHRA-SEC\deploy\snort\snort.wsl.conf` — the **sibling**
project directory, not this repository. Its `local.rules` is byte-identical to
this one today, but the configs added here have **no effect on the running
sensor** until step 6 repoints the pipeline.

---

## 10. Database

Schema unchanged; no migration needed. `snort_alerts` already carries
signature id, generator id, message, source, destination, protocol, ports,
severity, timestamps and review state — everything a port-scan alert needs.

Existing indexes were checked and **none was added**. The task's instruction
not to add indexes without checking applies: the alert tables are small (311
Snort alerts, 2,010 anomalies) and no query plan showed a missing index.

Historical alerts were preserved in full. The 173 inbound false positives
described in §3.2 were **not** deleted — they are real records of what the
sensor concluded at the time, and rewriting security history to make a fix
look better would be worse than the defect. They remain queryable, and the
corrected rule governs new detections only.

---

## 11. Full suite result

```
2742 passed, 3 warnings in 5475.24s
```

| Run | Result |
|---|---|
| Baseline, before any change | 2,713 passed, 0 failed |
| After all changes | **2,742 passed, 0 failed** |

2,713 + 29 new tests = 2,742. Nothing regressed and nothing was displaced.

The three warnings are pre-existing and unrelated: a `DeprecationWarning` from
`datetime.strptime` in the Snort text parser, which parses `alert_fast`
timestamps that carry no year (`10/06-21:49:01`). Snort's own format omits it.
Worth fixing before Python 3.15 changes the default, but out of scope here.

The 91-minute wall time is not a performance signal — the run overlapped with
the live negative test and several database queries competing for the same
MariaDB instance and CPU. The baseline run of the same suite took 7 minutes.

---

## 12. Remaining limitations

1. **The positive SPAN test is unexecuted** (§7). Until it runs, the claim
   "AETHRA-SEC detects port scans between other hosts" is **supported by
   mechanism and by parser-level evidence, not by an end-to-end trial.**
2. **Snort configs are not machine-validated** — no Snort binary in WSL here.
3. **The running sensor uses the sibling project's config** (§9).
4. **The capture feeding Snort is pinned by positional index** (§3.3), which
   is not stable across reboots or adapter changes.
5. **UDP port-scan gating is an approximation** (§3.2) — a UDP scan confined
   to ports ≥ 49152 is not counted by AETHRA's own rule. `sfportscan` is not
   subject to this.
6. **The alert file is 87 MB** and grows without rotation on the Windows side.
   Not addressed here; worth a retention policy.
7. **`sense_level medium`** in `sfportscan` is a documented default, not a
   value tuned against a measured false-positive rate on this network.
8. **No interface-role UI was built.** Visibility state and the health
   reporting are implemented; a Management/Monitoring role picker in Settings
   is not. The monitoring interface is selected through the existing capture
   interface picker, and the role concept lives in the Snort configs and this
   document. Stated plainly rather than left to be discovered.
