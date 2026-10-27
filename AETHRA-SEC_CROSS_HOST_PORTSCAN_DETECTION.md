# AETHRA-SEC — Cross-Host Port-Scan Detection

**Date:** 7 October 2026
**Requirement:** detect an authorised port scan between two devices that are
**both different from the AETHRA-SEC machine**, and show it as a real IDS alert.

```
192.168.100.10  ──port scan──►  192.168.100.222
                      │
                      │ mirrored by the switch (SPAN/TAP)
                      ▼
          AETHRA-SEC monitoring interface
                      │
                      ▼
                    Snort
                      │
                      ▼
            REAL port-scan alert
                      │
                      ▼
        IDS Alerts → MariaDB → Dashboard → Mitigation
```

**Headline status:** the software path is implemented, repaired and tested.
The **end-to-end trial is NOT EXECUTED — SPAN/HARDWARE DEPENDENCY**: this
machine has no managed switch with a mirror session and no second NIC. No
alert was simulated to stand in for it, and nothing below is marked PASS on
the strength of a guess.

---

## 1. The three concepts this document keeps apart

| | Question | Decided by |
|---|---|---|
| **Network visibility** | Do the packets reach the capture interface? | Where the sensor is plugged in |
| **Packet capture** | Can Npcap/TShark read the frames that arrive? | Driver, privileges |
| **Port-scan detection** | Does a rule match the frames that were read? | Snort config, `HOME_NET`, rules |
| **Application content** | Is the payload readable? | Encryption — *not* the capture point |

A failure in the first cannot be fixed by improving the others, and none of
them makes TLS payload readable.

---

## 2. Existing architecture, traced at runtime

Followed through the running processes, not inferred from filenames:

```
   Windows                                        WSL (Ubuntu-22.04)
   ───────                                        ──────────────────
   tshark ring buffer                             snort_pcap_pipeline.sh
     -b duration:10 -b files:30        ────────►    snort -c <conf> -r <chunk> -q
     -w C:\Snort-wsl\capture\cap.pcap                      │
          │                                               ▼
          │ (separate: AETHRA's own capture)       appends alert_fast lines to
          ▼                                        C:\Snort-wsl\log\alert
   PacketCaptureService ──► PacketView                     │
          │                   ├─ AnomalyRuleEngine         ▼
          │                   └─ PeerVisibilityTracker  SnortService (tails file)
          ▼                                                 │
   traffic_anomalies                                 parser.parse_fast
   (AETHRA's own analytics)                                 │
                                                            ▼
                                                     snort_alerts (MariaDB)
                                    ┌───────────────────────┼───────────────┐
                                    ▼                       ▼               ▼
                              IDS Alerts UI          Dashboard count   Notification
                                                            │
                                                            ▼
                                                    Mitigation mapping
```

Three facts that are easy to assume wrongly:

* **AETHRA-SEC does not launch Snort.** `snort_service.py` spawns no process
  for it; Snort is started by an external WSL script and AETHRA-SEC consumes
  its alert file. Closing the application does not stop Snort, and there is no
  risk of this work introducing a duplicate Snort process.
* **Snort does not capture live.** It runs `-r` over 10-second pcap chunks a
  Windows-side tshark ring buffer produces. **Snort therefore sees exactly
  what that tshark captured** — the capture point alone determines what the IDS
  can ever detect. It also means SPAN support needs no change to Snort: point
  the ring buffer at the monitoring NIC and Snort follows.
* **There are two independent detectors.** `AnomalyRuleEngine` writes
  `traffic_anomalies` (`RULE-PORT-SCAN` and friends); Snort writes
  `snort_alerts`. The IDS Alerts screen shows the second.

### Verified live

```
10/06-21:49:01.887690  [**] [1:1000002:2] TCP SYN (any port) [**] ... {TCP}
192.168.100.254:58737 -> 192.168.100.31:7070
```
persisted as `snort_alerts` #310. The pipeline works today, end to end, for
traffic aimed at this host.

---

## 3. Root cause — why cross-host scans were not detected

**Three independent blockers.** Fixing any one alone detects nothing. This is
the central finding.

### Blocker 1 — Visibility (physical, not software)

A switch forwards a unicast frame only towards the port its destination is on.
An ordinary switched port receives this host's traffic plus broadcast and
multicast, and nothing else. Promiscuous mode does not change it: it stops the
adapter discarding frames it was handed, and the switch was never going to
hand it these.

**Measured, 120 s on the ordinary Wi-Fi port:**

```
packets captured 3,987   drops 0
  involving this host        3,835
  broadcast / multicast        152
  between two other devices      0
other devices demonstrably present (their broadcast arrives): 20
```

Twenty devices provably on the segment; **not one frame** of their unicast.

### Blocker 2 — `HOME_NET` was a single host

```
ipvar HOME_NET 192.168.100.31/32
```
with every rule written `-> $HOME_NET`. Even with perfect mirroring, a scan
`192.168.100.10 → 192.168.100.222` matches **no rule**: the destination is not
in `HOME_NET`. Correct for an endpoint sensor, and the reason this host's own
browsing is not reported as an attack on itself — but it cannot also serve
network monitoring.

### Blocker 3 — No port-scan signature existed

`local.rules` held SIDs 1000001–1000010: ICMP echo, TCP SYN, DNS, HTTP/HTTPS
SYN, four flood rules. **No port-scan rule and no `sfportscan`.**

A Snort *rule* cannot express the question: `threshold` counts matching
events, not distinct destination ports, so a threshold rule on SYNs is a
SYN-rate rule — which sid 1000007 already was.

---

## 4. Defects found and repaired

### 4.1 Port-scan alerts were silently discarded *(critical)*

`sfportscan` reports its pseudo-packet as `{PROTO:255}`. The protocol group in
the `alert_fast` regex was `[A-Za-z0-9_-]+` — **no colon** — so the group
failed, the line failed to match, and `parse_fast` returned `None`.

Enabling the preprocessor without this fix would have dropped **every**
port-scan alert before the database, with no error and no record. Repaired and
verified against four variants; both endpoints survive as the *other* hosts:

```
gid=122 sid=1   192.168.100.10 -> 192.168.100.222   (portscan) TCP Portscan
gid=122 sid=3   192.168.100.10 -> 192.168.100.222   (portscan) TCP Portsweep
gid=122 sid=5   10.0.0.5       -> 10.0.0.9          (portscan) TCP Filtered Portscan
gid=122 sid=17  10.0.0.5       -> 10.0.0.9          (portscan) UDP Portscan
```

This is the single most important repair in this work: it is what makes
requirement Part 6 — *source stays `.10`, destination stays `.222`* —
actually hold.

### 4.2 `RULE-PORT-SCAN` counted replies as scanning *(high)*

AETHRA's own rule ran on every TCP/UDP packet, with no connection-attempt
gate. A server answering 20 outbound connections lands on 20 distinct
ephemeral ports — indistinguishable from one source touching 20 ports:

```
192.168.100.202 contacted 20 distinct destination port(s) on 192.168.100.31
ports: 53419, 53420, 53421, … 53438
```

**Across all 173 inbound detections on this installation:** 0 touched a
well-known service port; 173 hit only client-side ports; median share of
consecutive port numbers **95%**. Every one was reply traffic.

Outbound detections — this host's own authorised Nmap runs — were correct
throughout: **133 of 151** touched service ports. The logic was sound; the
input was wrong.

Repaired with a connection-attempt gate: TCP must be SYN-without-ACK (exact);
UDP must target a port below 49152. **Measured after:** 0 inbound, 2 genuine
outbound with intact service-port signatures.

### 4.3 Capture feed pinned by positional index *(medium — operator-owned)*

```
tshark -i 2 -w C:\Snort-wsl\capture\cap.pcap -b duration:10 -b files:30
```

`-i 2` indexes `tshark -D`, whose ordering is not stable. On this machine now,
index 2 is `Local Area Connection* 11`; the running dumpcap child has the
Wi-Fi device pinned explicitly, so it resolved differently at launch. Must be
pinned to the NPF device GUID before the monitoring NIC is relied on (§9).

Demonstrated during this work: the machine moved networks mid-session and
Wi-Fi went from `192.168.100.31` to `192.168.1.26`. The **device GUID and MAC
did not change** — which is exactly why roles are keyed on them.

---

## 5. Management and monitoring interfaces

`aethra_sec/analytics/interface_roles.py`, with three new settings:

| Setting | Meaning |
|---|---|
| `capture.monitoring_interface` | Capture device of the NIC wired to the SPAN/TAP |
| `capture.management_interface` | Capture device carrying the application's own traffic |
| `capture.monitoring_span_declared` | Operator's statement that the mirror exists — **intent, never proof** |

Properties that matter, each pinned by a test:

* **Identity is the stable capture device name** (`\Device\NPF_{GUID}`), never
  the friendly label. Asserted structurally: `resolve()` must not reference
  `display_name`.
* **A configured adapter that is absent is reported as missing**, never
  silently replaced. Falling back is how a sensor monitors the wrong segment
  while reporting success.
* **A monitoring interface with no IP is normal** — a SPAN destination is
  receive-only. Reported as `N/A`, not invented.
* **Nothing alters host networking.** Asserted by scanning the module for
  `subprocess`, `netsh`, `route`, `ipconfig`, `os.system`. No routing change,
  no gateway change, no address assignment.
* **One adapter in both roles is valid**, not an error — that is an endpoint
  sensor, and it is reported as such.

Addresses are joined from the OS by **MAC**, because the capture list (TShark)
carries the stable device but no addresses, and the adapter list (psutil)
carries addresses but an unstable name. Joining on MAC gives both without
trusting either name.

---

## 6. Capture visibility

`aethra_sec/analytics/capture_visibility.py` derives state from frames
actually captured, via the existing `PeerVisibilityTracker`:

| State | Meaning | Claims to see other hosts |
|---|---|---|
| `CAPTURE_UNAVAILABLE` | Npcap/TShark cannot capture here | No |
| `UNKNOWN` | Under 200 frames — nothing measured yet | No |
| `LOCAL_ONLY` | This host's traffic plus broadcast/multicast only | No |
| `MIRRORED_TRAFFIC` | Monitoring role declared, **no transit frame yet** | **No** |
| `TRANSIT_OBSERVED` | Real frames seen where neither endpoint is this host | **Yes** |

**The decisive guard, held by a parametrised test across frame counts from 0
to 500,000:** declaring a monitoring role can *never* produce
`TRANSIT_OBSERVED`. Selecting an interface is an intention; receiving a
third-party frame is evidence. `MIRRORED_TRAFFIC` is labelled **"MONITORING
INTERFACE SELECTED"** — never "SPAN CONFIGURED". The health probe additionally
requires the declared adapter to be **present**, so a declaration about an
absent NIC raises nothing.

Reported through `HealthService._probe_capture` as facts separate from capture
state:

```
Capture:     CAPTURING        ← the sensor is working
Visibility:  LOCAL ONLY       ← and this is how much it can see
Transit:     NOT OBSERVED
```

---

## 7. Port-scan detection

**Snort (network-wide).** `sfportscan` is the only mechanism that answers
"many *distinct* ports from one source". Added to `snort.wsl.conf` scoped
`watch_ip { $HOME_NET }` — scans aimed at the protected host.

For scans **between two other hosts**, `snort.monitor.conf` widens `HOME_NET`
to the monitored segment via its own `home_net.monitor.conf` — deliberately a
different file from `home_net.conf`, which a Windows-side updater rewrites
with this host's `/32`. One shared file would have the updater silently narrow
monitoring mode back to a single host.

The configs are separate because widening `HOME_NET` in the endpoint config
would also widen the broad single-packet rules (1000001–1000005) to every pair
of hosts on the segment, reintroducing the false positives those rules were
narrowed to avoid.

`ignore_scanners` is deliberately **not** set: this host's own authorised Nmap
assessments are real port scans and are reported as such. A sensor that hides
scans from one address cannot report that address being misused.

**AETHRA's own rule** (`RULE-PORT-SCAN`, 20 distinct ports in 10 s,
direction-agnostic) is unchanged in intent and now gated per §4.2.

---

## 8. Alert content, persistence and UI

No schema change and no migration. `snort_alerts` already carries generator
id, signature id, revision, message, source, destination, protocol, ports,
severity, timestamps and review state — everything the requirement lists.
Inserts use the existing parameterised repository.

A cross-host port-scan alert therefore reaches the existing IDS Alerts screen
through the existing workflow, with the existing actions, RBAC and audit
logging. **No separate "port scan demo" panel was created**, no counter was
introduced alongside the database, and the dashboard continues to count from
persisted rows.

**One honest display note:** `sfportscan` reports protocol as `PROTO:255` — a
pseudo-packet, not TCP. That raw value is stored as Snort emitted it rather
than being rewritten to "TCP", which would be inference. The scan type is
carried in the signature text (`TCP Portscan`, `TCP Portsweep`). Changing it
to display "TCP" would require a deliberate mapping decision and has not been
made unilaterally.

---

## 9. Wiring the monitoring NIC

AETHRA-SEC configures only its own side and never reconfigures a switch.

1. **Second NIC.** No IP needed — a SPAN destination is receive-only. Do not
   make it the default route; the management NIC keeps all connectivity.
2. **Switch.** Monitor session: *source* = the ports or VLAN carrying the
   traffic; *destination* = the port the monitoring NIC is on. Mirror **both
   directions**.
3. **Confirm frames arrive first:**
   ```
   tshark -D
   tshark -i \Device\NPF_{GUID} -c 50
   ```
   You must see frames where source and destination are both *other* hosts.
   If not, stop — nothing downstream can compensate.
4. **Repoint the capture feeding Snort, by GUID not index** (§4.3):
   ```
   tshark -i \Device\NPF_{GUID} -w C:\Snort-wsl\capture\cap.pcap -b duration:10 -b files:30
   ```
5. **Set the monitored range:** copy `deploy/snort/home_net.monitor.conf.example`
   to `C:\Snort-wsl\home_net.monitor.conf`, set `ipvar HOME_NET` to the
   authorised range and only that range.
6. **Point the pipeline at `snort.monitor.conf`** and validate with
   `snort -T -c <conf>` first.
7. **In AETHRA-SEC**, set `capture.monitoring_interface` to the device,
   `capture.monitoring_span_declared` to true, and start capture. Visibility
   reads *MONITORING INTERFACE SELECTED* until a real third-party frame
   arrives, then *TRANSIT TRAFFIC OBSERVED*. If it never changes, the mirror
   is not delivering — and the application says so rather than claiming
   network-wide visibility.
8. **Run the authorised scan** between two hosts inside the authorised range.

**Configuration-ownership split:** the Snort instance feeding this
installation reads
`C:\xampp\htdocs\AETHRA-SEC\deploy\snort\snort.wsl.conf` — the **sibling**
project, not this repository. Its `local.rules` is byte-identical today, but
the configs added here have **no effect on the running sensor** until step 6.

---

## 10. Test results

### Negative test — no SPAN *(REQUIRED, EXECUTED, PASS)*

120 s on an ordinary switched Wi-Fi port:

```
captured 3,987   drops 0   queue depth 0
  own 3,835   broadcast/mcast 152   peer unicast 0
  other devices present but unobservable: 20

visibility       : LOCAL_ONLY ("LOCAL ONLY")
transit traffic  : NOT OBSERVED
sees other hosts : False
snort_alerts     : 311 -> 311  (+0)      ← nothing fabricated
```

| Assertion | Result |
|---|---|
| Does not claim network-wide visibility | **PASS** |
| Transit reads NOT OBSERVED | **PASS** |
| No port-scan alert manufactured | **PASS** |
| Operator told SPAN/TAP is required | **PASS** (visibility detail text) |

### Positive test — SPAN *(NOT EXECUTED — NETWORK/SPAN DEPENDENCY)*

No managed switch with a mirror session and no second NIC on this machine.
Procedure in §9. **Not marked PASS. Not simulated.**

### Snort config validation *(NOT EXECUTED — TOOL DEPENDENCY)*

`wsl -e snort -V` → `execvpe(snort) failed: No such file or directory`. The
Snort binary is not present in WSL here, so `snort -T` could not be run. The
configs follow Snort 2.9 syntax matching the existing file but are **not
machine-validated.**

### Automated

| Run | Result |
|---|---|
| Baseline, before this work | 2,713 passed |
| After the parser/rule repairs | 2,742 passed |
| `tests/test_network_visibility_port_scan.py` | **38 passed** |
| Full suite, after the role work | **2,751 passed, 0 failed** |

---

## 11. Files changed

| File | Change |
|---|---|
| `aethra_sec/analytics/capture_visibility.py` | **new** — visibility states from captured frames |
| `aethra_sec/analytics/interface_roles.py` | **new** — management/monitoring roles by stable device |
| `aethra_sec/config/defaults.py` | three interface-role settings |
| `aethra_sec/integrations/snort/parser.py` | admits `PROTO:255`; GID 122 alerts no longer dropped |
| `aethra_sec/analytics/anomaly_rules.py` | `_initiates()` gate — counts connection attempts, not replies |
| `aethra_sec/services/health_service.py` | `capture_visibility` + `interface_roles` probes |
| `aethra_sec/core/application.py` | wires the tracker and `_interface_roles()` |
| `deploy/snort/snort.wsl.conf` | `sfportscan`, scoped to `$HOME_NET` |
| `deploy/snort/snort.monitor.conf` | **new** — monitoring-mode config |
| `deploy/snort/home_net.monitor.conf.example` | **new** — segment-scoped template |
| `tests/test_network_visibility_port_scan.py` | **new** — 38 regression tests |
| `sql/aethra_sec_schema.sql` | regenerated for the three new settings (5-line diff) |

No migration. No historical alert altered or deleted. No index added — the
alert tables are small and no plan showed a missing one.

The 173 inbound false positives in §4.2 were **not** deleted. They are real
records of what the sensor concluded at the time; rewriting security history
to make a fix look better would be worse than the defect. The corrected rule
governs new detections only.

---

## 12. Wireshark

Wireshark and AETHRA-SEC share the same capture ecosystem and the same
limitation. Stated accurately:

> Wireshark cannot capture traffic that is not delivered to its capture
> interface. With an appropriate monitoring point such as SPAN or a TAP,
> Wireshark can capture and analyse mirrored traffic.

AETHRA-SEC follows the same principle. On an ordinary switched port neither
tool sees unrelated-host unicast; with a mirror both do. It is not a defect in
either, and "Wireshark cannot detect other devices" would be wrong.

### HTTPS

Mirrored traffic makes **metadata** observable — addresses, ports, protocol,
DNS where unencrypted, TLS SNI where present, sizes and timing. **TLS payload
stays encrypted.** AETHRA-SEC cannot read another user's HTTPS search terms,
page content or credentials. No TLS interception is implemented and none is
planned here.

---

## 13. Full suite result

```
2751 passed, 3 warnings in 399.94s
```

| Run | Result |
|---|---|
| Baseline, before any of this work | 2,713 passed |
| After the parser and rule repairs | 2,742 passed |
| After the interface-role work | **2,751 passed, 0 failed** |

2,713 + 38 new tests = 2,751. Nothing regressed.

**One self-inflicted failure, caught and fixed.** The run before this one
reported two failures in `tests/test_schema_export.py`. They were mine: adding
three settings to `defaults.py` left `sql/aethra_sec_schema.sql` stale, and
that test exists precisely to catch it. Regenerated with
`python scripts/export_schema.py`; the diff was **five lines** - the three new
settings rows and the count moving 72 to 75. No table and no existing row was
touched. Verified before accepting.

The three warnings are pre-existing and unrelated: `datetime.strptime` parsing
Snort `alert_fast` timestamps, which carry no year by format.

---

## 14. Acceptance criteria

| Criterion | Status |
|---|---|
| Dedicated monitoring interface can be selected | **Implemented** (settings + resolver) |
| Normal operation continues via management interface | **Implemented** — nothing alters routing |
| Snort can inspect monitoring-interface traffic | **Implemented** — pcap-chunk design needs only the ring buffer repointed |
| Scanner need not be AETHRA-SEC | **Implemented** |
| Target need not be AETHRA-SEC | **Implemented** — `watch_ip` widened in monitor config |
| Source/destination/protocol/timestamp preserved | **Implemented and tested** (§4.1) |
| Real Snort port-scan alert generated | **NOT EXECUTED — SPAN dependency** |
| Alert reaches, persists, displays | **Path verified**; cross-host instance not executed |
| Dashboard/badge update from database | **Unchanged existing behaviour** |
| Mitigation mapping used | **Unchanged existing behaviour** |
| Transit classified correctly when observed | **Implemented** (existing `Direction.TRANSIT`) |
| No false network-wide visibility claim | **Tested, PASS** |
| No fake alerts / packets / statistics | **Tested, PASS** |
| No-SPAN negative case handled honestly | **Tested, PASS** |
| SPAN positive case | **NOT EXECUTED — NETWORK/SPAN DEPENDENCY** |
| Existing tests still pass | **2,751 passed, 0 failed** |
| No duplicate Snort processes | **By design — AETHRA never spawns Snort** |
| No historical data deleted | **Confirmed** |

---

## 15. Known limitations

1. **The end-to-end cross-host trial is unexecuted.** Until it runs, "detects
   port scans between other hosts" is supported by mechanism, by parser-level
   evidence and by the negative control — **not** by a completed trial.
2. **Snort configs are not machine-validated** (no binary in WSL here).
3. **The running sensor uses the sibling project's config** (§9).
4. **The capture feeding Snort is pinned by positional index** (§4.3).
5. **UDP scan gating is an approximation** — a UDP scan confined to ports
   ≥ 49152 is not counted by AETHRA's own rule. `sfportscan` is not affected.
6. **No interface-role UI.** Roles are settings keys with a resolver and
   health reporting; a Management/Monitoring picker in the Settings screen was
   not built. Stated plainly rather than left to be discovered.
7. **`sense_level medium`** is a documented default, not a value tuned against
   a measured false-positive rate on this network.
8. **The alert file is 87 MB** and is not rotated on the Windows side.
9. **`PROTO:255` is displayed raw** for sfportscan alerts (§8).
