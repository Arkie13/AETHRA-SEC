# Snort integration

AETHRA-SEC **consumes** alerts from a Snort sensor you run. It does not start
Snort, does not write Snort rules, and cannot produce an alert of its own. If
no sensor is emitting, the Alerts screen stays empty and System Health reports
*"Snort unavailable"* — that is the honest state, not a failure to display
something (§1, §21).

---

## 1. Choosing a transport

| Transport | `AETHRA_SNORT_TRANSPORT` | Where it fits |
| --- | --- | --- |
| Alert Socket IPC | `unixsock` | Linux/WSL sensor. Snort's `alert_unixsock` plugin sends one binary `Alertpkt` datagram per alert. This is the mechanism named in the system design |
| Alert file tail | `file` | **Simplest on Windows.** AETHRA-SEC tails `alert_fast` / `alert_csv` / `alert_json` output, following truncation and rotation |
| UDP syslog | `syslog` | Sensor uses `alert_syslog` and forwards to this workstation; works across machines and on Windows |
| TCP | `tcp` | Sensor (or a shipper) forwards line-oriented alert text over TCP; AETHRA-SEC listens |
| None | `disabled` | No ingest. Everything else in the application still works |

All four are read-only consumers. None of them can reach the sensor, change its
configuration, or ask it for anything.

---

## 2. Configuration

### `unixsock` — Alert Socket IPC (Linux / WSL)

`snort.conf`:

```
output alert_unixsock
```

Snort creates `snort_alert` in its log directory (commonly
`/var/log/snort/snort_alert`) and writes one `Alertpkt` datagram per alert.

`.env`:

```ini
AETHRA_SNORT_TRANSPORT=unixsock
AETHRA_SNORT_SOCKET_PATH=/var/log/snort/snort_alert
```

AETHRA-SEC binds the socket, so start it **before** Snort — Snort connects to
an existing socket and will report an error if it is absent. The process needs
write access to the directory holding the socket.

### `file` — tail an alert file (recommended on Windows)

`snort.conf` (choose one):

```
output alert_fast: alert.ids
output alert_csv:  alert.csv timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,priority,class
output alert_json: alert.json                # Snort 3
```

`.env`:

```ini
AETHRA_SNORT_TRANSPORT=file
AETHRA_SNORT_ALERT_FILE=C:\Snort\log\alert.ids
```

The tail starts at the end of the existing file, so a large historical file is
not replayed as if it had just happened. Truncation and rotation are detected
and followed.

### `syslog` — UDP syslog listener

`snort.conf`:

```
output alert_syslog: LOG_AUTH LOG_ALERT
```

Point the sensor's syslog at this workstation, then:

```ini
AETHRA_SNORT_TRANSPORT=syslog
AETHRA_SNORT_SYSLOG_HOST=0.0.0.0
AETHRA_SNORT_SYSLOG_PORT=5514
```

Ports below 1024 need elevation; 5514 avoids that. Allow the port through the
firewall on the AETHRA-SEC workstation only.

### `tcp` — TCP listener

```ini
AETHRA_SNORT_TRANSPORT=tcp
AETHRA_SNORT_TCP_HOST=127.0.0.1
AETHRA_SNORT_TCP_PORT=9000
```

AETHRA-SEC listens and accepts line-oriented alert text. Bind to `127.0.0.1`
unless the sensor is on another machine, and restrict the port at the firewall.

---

## 3. Alert formats

`parse_alert_line()` auto-detects, per line:

* **`alert_fast`** — the classic one-liner:

  ```
  01/15-14:22:31.123456  [**] [1:2001219:19] ET SCAN Potential SSH Scan [**]
  [Classification: Attempted Information Leak] [Priority: 2]
  {TCP} 192.168.1.50:44321 -> 192.168.1.25:22
  ```

* **`alert_csv`** — column list from the configuration, or from a header row
  when present; the default column order is assumed otherwise.
* **`alert_json`** — Snort 3's JSON events.
* **Syslog-wrapped** variants of any of the above.

Fields the sensor did not supply stay empty rather than being guessed, and the
**raw line is always retained** in `snort_alerts.raw_alert` as evidence.

### The binary `Alertpkt`

`Alertpkt` is a C structure whose layout depends on the build:

```c
typedef struct _Alertpkt {
    uint8_t  alertmsg[256];      /* NUL-padded rule message   */
    struct pcap_pkthdr pkth;     /* timeval + caplen + len    */
    uint32_t dlthdr, nethdr, transhdr, data, val;
    uint8_t  pkt[SNAPLEN];       /* the offending packet      */
    Event    event;              /* gid / sid / rev / prio    */
} Alertpkt;
```

Two build-time differences break a naive `struct.unpack`, and both are handled:

* `SNAPLEN` is a compile-time constant, so `event` sits at a different offset
  in different builds. The decoder anchors `Event` at the **end** of the
  datagram, which is correct for any snap length.
* `struct timeval` is 8 bytes on 32-bit builds and 16 on 64-bit ones. Both
  layouts are tried and the one yielding plausible values is used; the layout
  actually used is recorded with the alert.

The embedded packet is decoded only as far as the IPv4/TCP/UDP headers, to
recover the endpoints. If a datagram does not decode into sensible values it is
**refused** and counted as a parse failure — visible on the Alerts and System
Health screens — rather than being stored as a half-decoded alert.

---

## 4. What AETHRA-SEC does with an alert

1. **Normalise.** GID/SID/rev, message, classification, priority, protocol and
   endpoints are mapped onto `SnortAlert`. Both `alert_time` (the sensor's own
   timestamp) and `received_at` are kept, with `time_source` recording which
   one is authoritative.
2. **Map severity.** Snort priority → severity, deterministically. Nothing is
   inferred or upgraded.
3. **Deduplicate.** `dedup_key = gid:sid:src_ip:dst_ip:dst_port`. A repeat
   inside `detection.suppression_window_seconds` increments `duplicate_count`
   on the stored alert instead of creating a new row, so a chatty signature
   does not flood the screen or distort the counts.
4. **Resolve hosts.** Source and destination are linked to `hosts` when those
   addresses are already known.
5. **Correlate.** The correlation engine may attach the alert to an incident,
   alongside traffic anomalies and Nmap findings. The incident states its
   evidence provenance exactly — "Snort only" when Snort is the sole source,
   "Snort + Nmap" when a scan finding corroborates it.
6. **Recommend.** Mitigation guidance is looked up by threat category and
   presented as advice. Nothing is applied.

---

## 5. Verifying ingest

**System Health** shows the transport, its state, when it last received
something, and the parse-failure count. Check there first.

On Linux you can confirm the socket path end-to-end without a sensor by
sending a datagram to the configured socket with a small script that builds an
`Alertpkt` (`aethra_sec.integrations.snort.alertpkt.build_alertpkt` exists for
exactly this, and is what the test suite uses). Anything that arrives is
processed by the same code path a real sensor drives.

For the `file` transport, appending a well-formed `alert_fast` line to the
configured file is enough to see the tail, parser and storage path work.

> These checks confirm the **transport**. They are not a substitute for a real
> sensor, and nothing produced this way should be presented as a detection —
> the stored alert records the transport it arrived on.

---

## 6. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| "Snort unavailable" while Snort runs | `AETHRA_SNORT_TRANSPORT` is `disabled`, or points at a path/port the sensor is not using |
| `unixsock`: Snort logs "could not connect to socket" | AETHRA-SEC was not running when Snort started. Start AETHRA-SEC first, then Snort |
| `unixsock` on Windows | Not available — Windows has no Unix domain sockets. Use `file` or `syslog` |
| File transport sees nothing | Wrong path, or Snort is writing a different output (e.g. unified2, which is binary and not tailed). Confirm the file grows while traffic flows |
| Alerts arrive with no source or destination | The sensor's format omitted them, or the embedded packet was not IPv4. The raw alert is retained; nothing is filled in |
| Parse failures climbing | The format is not one of the four supported. Switch the sensor to `alert_fast`, `alert_csv` or `alert_json` |
| Alert count much lower than the sensor's | Deduplication is folding repeats. Check `duplicate_count` on the stored alert and `detection.suppression_window_seconds` |
| Timestamps off by hours | The sensor's clock or timezone differs. `received_at` and `time_source` show which timestamp AETHRA-SEC trusted |
