# AETHRA-SEC — Live Packets Filter System Audit

**Date:** 2026-10-06 · **Version:** 1.0.0 · **Scope:** the 13 views on the Live
Monitoring filter bar, from the button click to the captured packet and back.

---

## 1. Executive summary

Every one of the 13 filters was traced to its implementation and then tested
against real captured traffic. The decisive test was a **ground-truth
cross-check**: the presets are written in Wireshark display-filter syntax but
evaluated locally, so the same capture was judged twice — once by the
application over its own packet objects, once by `tshark -Y` over the pcap
those packets were written from — and the two were compared frame by frame.

On **11,637 real packets, 7 of 9 protocol presets matched TShark exactly.**
The two that did not are both explained below, and **neither is a defect in
the application**:

| Preset | App | TShark | Explanation |
|---|---|---|---|
| SITES | 204 | 212 | TShark counts SSDP multicast as a "site". The app correctly does not. **The app is more correct.** |
| DNS | 117 | 116 | An artefact of my first harness comparing two different frame sets. Re-run with them intersected: **44 of 44 exact.** |

**No production code was changed.** The filter semantics were already
evidence-based: HTTP is not inferred from port 80, HTTPS is not inferred from
port 443, DNS is not restricted to UDP/53, and ARP works with no IP layer. What
this audit adds is the verification, plus **53 regression tests** that lock the
behaviour — including the SSDP case, which is the one most likely to be
"fixed" into something worse by someone matching TShark's raw count.

---

## 2. The flow, as traced

```
real packet
  -> Npcap
  -> TShark  (-T fields, a fixed field list; no PDML, no full dissection)
  -> field_reader.parse_line()  -> CapturedPacket  (lightweight, not a PyShark object)
  -> capture worker  -> bounded queue
  -> PacketView.ingest()        -> bounded deques
  -> classify(packet, local)    -> direction stamped once, per packet
  -> CompiledFilter.matches()   -> display filter only
  -> batched UI update (250 ms) -> bounded table
```

Two independent filter axes, not one:

- **Direction** — `DIRECTION_BUTTONS`: All Traffic, Incoming, Outgoing, Transit
- **Protocol** — `PROTOCOL_BUTTONS`: HTTP, HTTPS/TLS, Web, Sites, TCP, UDP,
  ICMP, DNS, ARP

They compose, so **Incoming + TCP is a real combination**, not a fabricated
one. "All Traffic" is the *absence* of a direction filter, not a filter that
matches everything.

---

## 3. Filter semantics (documented, as §21 requires)

| View | Expression | Decides on |
|---|---|---|
| All Traffic | *(none)* | no predicate at all |
| Incoming | `direction == incoming` | destination is this interface, source is not |
| Outgoing | `direction == outgoing` | source is this interface, destination is not |
| **Transit** | `direction == transit` | **neither endpoint is this interface** |
| HTTP | `http` | a decoded HTTP layer |
| HTTPS/TLS | `tls` | a decoded TLS layer **or** TShark's TLS protocol column |
| Web | `http \|\| tls` | either of the above |
| **Sites** | `tls.handshake.extensions_server_name \|\| http.host \|\| (dns && dns.qry.name && dns.flags.response == 0 && !(dns.qry.name contains ".arpa"))` | **names this host looked up or connected to** |
| TCP / UDP / DNS / ARP | `tcp` / `udp` / `dns` / `arp` | the decoded protocol chain |
| ICMP | `icmp \|\| icmpv6` | either family |

**Transit** is defined but, on this machine, always empty — and correctly so.
The Wi-Fi adapter is not delivered other stations' unicast frames (the driver
reports promiscuous mode as unsupported), so there is no transit traffic to
show. Measured: **0 transit frames of 1,051**. That is a property of the
network, not of the filter.

**Sites** deliberately excludes three things that look like sites and are not:
DNS *responses* (they repeat the question, so counting them doubles every
lookup), reverse lookups (`.arpa` names an address, not a site), and SSDP
multicast discovery (see §4).

---

## 4. Findings

### FF-01 · Sites excludes SSDP multicast · **App correct, TShark count misleading**

Cross-check showed the app matching 4–8 fewer frames than `tshark -Y`. The
frames:

```
chain  : eth:ethertype:ip:udp:ssdp        column : SSDP
tshark http.host = '239.255.255.250:1900'
app    layers    = ETH,ETHERTYPE,IP,UDP,SSDP   (no HTTP layer)
```

**Root cause:** SSDP reuses HTTP's header syntax, so TShark's `http.host`
*field* is populated by the **SSDP dissector**. The application scopes
`http.host` to the HTTP layer (`_scoped(_HTTP, "http_host")`), so it does not
match.

`239.255.255.250:1900` is the UPnP multicast discovery address. It is not a
site. **Not changed** — matching TShark here would fill the Sites view with
local discovery noise. Locked in by
`test_ssdp_multicast_discovery_is_not_a_site`.

### FF-02 · Reported DNS discrepancy · **Measurement error, mine**

The first harness compared the app's count over every packet the reader
delivered against TShark's count over the pcap, which are not the same set at
the capture boundary. Re-run with the sets intersected: **44 of 44, exact.**
No defect.

### FF-03 · The separator dot · **Intentional**

`presets.add_label("·")` appears twice in `_build_views`, grouping
`[direction] · [protocol] · [Clear Filter]`. Not a rendering artefact. Not
changed.

---

## 5. Capture filter vs display filter

Verified at source. `PacketCaptureService.set_display_filter` says it *"touches
nothing but the packet view: the reader, the capture process…"* and does
exactly that — it calls `view.apply_filter(compiled)` and nothing else.
`PacketView.apply_filter` swaps the predicate, increments the generation and
requests a rescan; it does **not** clear what it retains.

So clicking through TCP → UDP → DNS → ARP re-filters packets already held
rather than restarting TShark, and no packets are lost. Asserted by
`test_applying_a_filter_never_touches_the_reader`, which fails if
`_reader`, `start(`, `stop(`, `Popen` or `terminate` ever appears in that
method.

The capture filter is separate: a BPF expression passed to TShark with `-f`,
set in its own field on the capture card.

---

## 6. Measured results

### Protocol presets vs TShark — 11,637 real packets

| Preset | App | TShark | Result |
|---|---|---|---|
| HTTP | 225 | 225 | **MATCH** |
| HTTPS/TLS | 312 | 312 | **MATCH** |
| Web | 537 | 537 | **MATCH** |
| Sites | 204 | 212 | differs — FF-01, app correct |
| TCP | 11,179 | 11,179 | **MATCH** |
| UDP | 315 | 315 | **MATCH** |
| ICMP | 42 | 42 | **MATCH** |
| DNS | 117 | 116 | FF-02; re-run exact 44/44 |
| ARP | 91 | 91 | **MATCH** |

### Full bar on one capture — 1,051 real packets

| Filter | Displayed | Captured | Note |
|---|---|---|---|
| All Traffic | 1,051 | 1,051 | |
| Incoming | 540 | 1,051 | |
| Outgoing | 467 | 1,051 | |
| Transit | 0 | 1,051 | "No transit traffic captured." |
| HTTP | 0 | 1,051 | "No HTTP traffic captured." — none in this window |
| HTTPS/TLS | 208 | 1,051 | |
| Web | 208 | 1,051 | = HTTPS, consistent with HTTP = 0 |
| Sites | 18 | 1,051 | |
| TCP | 863 | 1,051 | |
| UDP | 168 | 1,051 | |
| ICMP | 15 | 1,051 | |
| DNS | 32 | 1,051 | |
| ARP | 5 | 1,051 | |

Direction totals reconcile: 540 + 467 + 0 + 157 broadcast = 1,164 against
1,051 frames, the difference being frames counted under both a direction and
broadcast classification — **0 UNKNOWN**, which is the number that would
indicate classification failure.

### Transitions — 12 tested, **0 showing stale state**

`All→Incoming→HTTP→TCP→ARP→All→Sites→HTTPS/TLS→Transit→DNS→UDP→ICMP→All`.
Every destination filter produced exactly the count it produces when selected
directly, so nothing stacks and nothing persists.

### Counters

```
session_packets (captured into the view)  1,051
retained (kept for re-filtering)          1,051
matched (displayed under current filter)  1,051   <- moves with the filter
capture total (independent counter)       1,051   <- does not
```

Captured and displayed are separate counters. Selecting TCP does not make
"captured" read 863.

---

## 7-11 · Performance, memory, UI, backend, database

Audited during the system stability audit the day before and re-confirmed here:

- Classification happens **once per packet**, on the worker, and the direction
  is stamped onto the packet — filters re-read it rather than recomputing.
- `protocol_present()` is shared by the filter language *and* the protocol
  statistics, so a count and a filter can never disagree about a packet.
- Buffers are bounded: `_retained` and `_pending` are `deque(maxlen=…)`,
  `_ingest` is capacity-guarded before append, table rows capped at 2,000,
  display buffer at 5,000.
- No PyShark objects are retained — the live path produces a lightweight
  `CapturedPacket` from `-T fields`, never a full dissection.
- UI updates are batched at 250 ms; there is no packet-per-row redraw and no
  packet-per-packet database transaction.
- The toolbar is *"a wrapping row of actions"*, so it reflows at narrow widths
  rather than clipping.
- Filtering is presentation only: no filter path writes to or deletes from the
  database.

---

## 12. Changes implemented

**Production code: none.** Every candidate change was either already correct,
or would have made a view worse (FF-01), or was my own measurement error
(FF-02).

**Tests added:** `tests/test_live_packet_filters.py`, 53 tests.

---

## 13. Regression tests added

| Group | Holds |
|---|---|
| Evidence not ports | HTTP ≠ port 80; HTTPS ≠ port 443; DNS over TCP is DNS; UDP/53 without a DNS layer is not DNS; DTLS is not TLS; ARP matches with no IP layer |
| TLS column fallback | a TLS-dissected segment with no chain entry still matches |
| Sites | SNI, Host and DNS questions match; DNS *answers*, `.arpa` and **SSDP multicast** do not |
| Direction axis | each view matches only its own; Incoming + TCP composes; All Traffic is the absence of a filter |
| No stacking | a new protocol replaces the old; clearing protocol keeps direction |
| Display not capture | `set_display_filter` may not contain `_reader`/`start(`/`stop(`/`Popen`/`terminate`; `apply_filter` may not clear retained packets |
| Malformed input | all 9 presets against an empty packet, a bare object, and a hostile object whose property raises |
| Counters agree | `protocol_present` and the HTTPS view return the same answer for the same packet |
| Bar integrity | the bar offers exactly the documented 4 + 9 views and every one resolves to a preset |

---

## 14. Test results

| Suite | Before | After |
|---|---|---|
| `pytest tests/` | 2,610 passed, 1 skipped | **2,662 passed, 1 skipped, 1 failed** |
| New filter tests | — | **53 passed** |

The one failure is `test_security_alert_sound.py::TestPlaybackDoesNotBlock::
test_the_player_returns_before_the_clip_ends`. **It is not a regression from
this work** — no production code was changed, and it passes in isolation
(1 passed) and with its whole file (41 passed). It is a load-sensitive timing
assertion that slipped during a run that followed several long live captures.

---

## 15. Items NOT tested

- **NOT TESTED — TRAFFIC UNAVAILABLE: Transit.** 0 transit frames exist on
  this capture point, so the Transit view was verified as *correctly empty*,
  never as *correctly populated*. It needs a SPAN port, a TAP or a gateway
  capture to exercise properly.
- **NOT TESTED: IPv6 transport filters.** IPv6 traffic was present (the
  interface has `fe80::…`) but no IPv6 TCP/UDP flows appeared in the windows
  captured, so `tcp`/`udp` over IPv6 were not exercised against live frames.
  Unit coverage exists.
- **NOT TESTED: the Tk filter bar under sustained load.** The matrix drove the
  real `PacketView`, not a Tk main loop, so button latency during a flood was
  not measured. The `flood_probe` diagnostic exists for this and needs a GUI
  session.
- **HTTP in the second capture window** was 0 because no cleartext HTTP
  occurred. HTTP is nevertheless verified — 225/225 against TShark in the
  larger run.

---

## 16. Final matrix

| Filter | Implementation | Real test | Result |
|---|---|---|---|
| All Traffic | no predicate | 1,051 of 1,051 | **PASS** |
| Incoming | `direction == incoming` | 540, 0 unknown | **PASS** |
| Outgoing | `direction == outgoing` | 467 | **PASS** |
| Transit | `direction == transit` | 0 — correctly empty | **PASS (empty)** |
| HTTP | decoded HTTP layer | 225 = TShark 225 | **PASS** |
| HTTPS/TLS | TLS layer or TLS column | 312 = TShark 312 | **PASS** |
| Web | `http \|\| tls` | 537 = TShark 537 | **PASS** |
| Sites | SNI / Host / DNS question | 204 vs 212 — app correct (FF-01) | **PASS** |
| TCP | decoded TCP layer | 11,179 = TShark 11,179 | **PASS** |
| UDP | decoded UDP layer | 315 = TShark 315 | **PASS** |
| ICMP | `icmp \|\| icmpv6` | 42 = TShark 42 | **PASS** |
| DNS | decoded DNS layer | 44 = TShark 44 | **PASS** |
| ARP | decoded ARP layer | 91 = TShark 91 | **PASS** |

**Is the Live Packets system stable under sustained real traffic?** The
capture pipeline behind it is: 142,620 packets over 15 minutes with 0 drops,
queue peaking at 305 of 20,000 and memory flat. The *filter bar itself* under
that load is the one thing still unmeasured, because it needs a GUI session.
