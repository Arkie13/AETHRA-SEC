# Running Snort against AETHRA-SEC

AETHRA-SEC does not launch Snort. It **listens** for the alerts Snort emits, so
Snort runs as its own process and the two are wired together by a socket path.
This directory holds a working minimal configuration.

## 1. Install Snort

```bash
sudo apt-get install -y snort          # Debian/Ubuntu, ships Snort 2.9
snort -V
```

## 2. Install this configuration

```bash
sudo mkdir -p /etc/aethra-snort /var/log/snort
sudo cp snort.conf local.rules /etc/aethra-snort/
sudo snort -c /etc/aethra-snort/snort.conf -T      # validate
```

`local.rules` holds three deliberately broad rules (ICMP echo, TCP SYN, UDP to
port 53). They exist to prove the ingest path end to end on a lab network; on a
real network replace them with a rule set suited to it, because rules this broad
will alert on ordinary traffic.

## 3. Point AETHRA-SEC at the alert socket

In `.env`:

```ini
AETHRA_SNORT_TRANSPORT=unixsock
AETHRA_SNORT_SOCKET_PATH=/var/log/snort/snort_alert
AETHRA_SNORT_PATH=/usr/sbin/snort
AETHRA_SNORT_CONFIG=/etc/aethra-snort/snort.conf
```

## 4. Start them in the right order

AETHRA-SEC **binds** the socket and Snort connects to it, so AETHRA-SEC starts
first. Start the application, then:

```bash
sudo snort -c /etc/aethra-snort/snort.conf -i <interface> \
           -A unsock -l /var/log/snort -q -N
```

The Alerts screen then shows `RUNNING · transport: unixsock`, and its counters
(received / stored / duplicates folded / parse failures) are live.

## Troubleshooting

**"could not bind" / ingest OFFLINE.** Another process already owns the socket
- usually a Snort left running from a previous session. `pkill snort`, remove
`/var/log/snort/snort_alert`, and restart AETHRA-SEC.

**Alerts received but none stored.** That is deduplication, not a fault: a flood
matching one rule folds into a single row whose `duplicates folded` counter
climbs. The Alerts screen shows both numbers.

**`-A unsock` vs `output alert_unixsock`.** Either works; the config here sets
the output plugin, and the command line flag makes the intent explicit.

---

## Running Snort in WSL (recommended on Windows)

The native Windows Snort 2.9.20 build has a known, currently unresolved
packaging problem: its `snort.exe` embeds a manifest that pins an exact,
16-years-obsolete `Microsoft.VC90.CRT` runtime version (9.0.21022.8) that no
current Windows redistributable installs — the app crashes at launch with
`STATUS_DLL_NOT_FOUND` (0xC0000135) and there is no clean fix short of
forging a private SxS assembly. **Use Snort inside WSL instead** — it is
the well-maintained path, avoids this native-Windows problem entirely, and
matches this project's primary-documented transport family. The section
below ("Running Snort on Windows") is kept only for completeness / in case
a future Windows build fixes the packaging bug.

Since AETHRA-SEC itself runs natively on Windows, `unixsock` still isn't
usable (a native process cannot dial a Unix domain socket living inside the
WSL2 VM). Use the `file` transport, but point Snort's log directory at a
path under `C:\` so it is the same file on both sides of the WSL boundary
(WSL sees `C:\` as `/mnt/c`) — no `unixsock`, no `\\wsl$` share needed.

### 1. Install WSL + Ubuntu 22.04

Ubuntu's own default WSL release (`Ubuntu`, currently 26.04) has dropped the
`snort` package; **Ubuntu 22.04 ("jammy") still ships classic Snort 2.9** in
its `universe` repo, so install that release specifically:

```powershell
wsl --install -d Ubuntu-22.04
```

First launch asks you to create a Linux username/password interactively —
do that once, then:

```bash
sudo apt-get update
sudo apt-get install -y snort
snort -V
```

The installer's debconf prompt asks for your capture interface and home
network — `eth0` and your local range are fine defaults; both can be
changed later in `/etc/snort/snort.conf`. Ubuntu also auto-starts a default
Snort service on install; stop it if you're going to run AETHRA-SEC's own
config instead: `sudo service snort stop`.

### 2. Why live `-i` capture inside WSL is not enough

The obvious approach — run `snort -i eth0` (or, with WSL2 "mirrored"
networking enabled, `-i eth<N>` bound to the host's real adapter) — only
gets you partway. It reliably sees traffic WSL itself sends/receives and
LAN broadcast/multicast (ARP, SSDP, mDNS), but **not third-party unicast
traffic addressed to the Windows host**, e.g. another machine on your LAN
attacking `192.168.100.31` directly. Confirmed on this project: a real UDP
flood from another host was invisible to `-i`-based live capture inside
WSL, even with mirrored networking working correctly, while PyShark
(native Windows capture) saw it immediately. This is a structural property
of how WSL2's virtual network interface receives packets, not a
misconfiguration - no rule tuning or interface fiddling fixes it.

### 3. The fix that works: feed Snort real captures via pcap files

Capture natively on Windows (the same Npcap path PyShark already uses
successfully - proven to see real third-party traffic) and hand the
resulting pcap files to Snort running in WSL for signature analysis in
read mode (`-r`), instead of live interface capture. Two pieces:

**A. A rolling native capture on Windows** (PowerShell, run as your normal
user - elevation is not required once Npcap is installed):

```powershell
New-Item -ItemType Directory -Force -Path "C:\Snort-wsl\capture"
& "C:\Program Files\Wireshark\tshark.exe" -D    # find your real adapter's index, e.g. "2. ... (Wi-Fi)"
Start-Process -FilePath "C:\Program Files\Wireshark\tshark.exe" `
    -ArgumentList '-i','2','-w','C:\Snort-wsl\capture\cap.pcap','-b','duration:10','-b','files:30' `
    -WindowStyle Hidden
```

This writes a 10-second rolling window of 30 pcap chunks (5 minutes of
history) to `C:\Snort-wsl\capture`.

**B. `snort_pcap_pipeline.sh`** (this directory) watches that folder from
inside WSL, runs each completed chunk through Snort in read mode, and
appends real, signature-matched alerts to the same output file the live
approach used - moving processed chunks into a `processed/` subfolder
(kept, capped at the last 50, for later inspection) as it goes:

```bash
sudo apt-get install -y snort    # if not already installed, see step 1 above
bash /mnt/c/xampp/htdocs/AETHRA-SEC/deploy/snort/start_pipeline.sh
```

`start_pipeline.sh` detaches the loop with `setsid`/`disown` so it survives
the invoking shell closing - `ps aux | grep pipeline` should show it
running independently afterward.

Verified end-to-end on this project: a real UDP flood from another LAN
host was captured by tshark, processed by the pipeline within one 10-second
cycle, and correctly fired the `UDP flood - possible DoS` rule - confirmed
both by reading the resulting alert file and by running AETHRA-SEC's actual
`AlertFileTransport` against it directly.

### 4. Point AETHRA-SEC at the output file

```ini
AETHRA_SNORT_TRANSPORT=file
AETHRA_SNORT_ALERT_FILE=C:\Snort-wsl\log\alert
AETHRA_SNORT_PATH=
AETHRA_SNORT_CONFIG=C:\xampp\htdocs\AETHRA-SEC\deploy\snort\snort.wsl.conf
```

`snort.wsl.conf` uses a bare `output alert_fast` (no filename) deliberately
- this Snort build has been observed to inconsistently honour an explicit
filename in that directive, silently falling back to its own hardcoded
default (`alert`, no extension) unpredictably often. The bare form makes
the output filename deterministic instead of fighting that; always confirm
with `Get-ChildItem C:\Snort-wsl\log` that `alert` (not `alert.ids` or
anything else) is the file actually growing before trusting
`AETHRA_SNORT_ALERT_FILE`.

`AETHRA_SNORT_ALERT_FILE` must already exist before AETHRA-SEC starts
tailing it - start the pipeline first, then start or restart AETHRA-SEC.

### WSL troubleshooting

**Nothing shows up despite real traffic.** Confirm both halves are alive:
`Get-Process tshark` on Windows (or check for it in Task Manager), and
`ps aux | grep pipeline` inside WSL. Check `C:\Snort-wsl\capture` is
actually accumulating chunks and `processed\` is growing too - if chunks
pile up unprocessed, the pipeline died; check `/tmp/pipeline.log` and
`/tmp/snort_pipeline_errors.log` inside WSL.

**Two Snort instances/output directives fighting over the output file.**
Don't pass `-A fast` on the command line *and* keep an `output alert_fast`
config directive at the same time - one wins unpredictably and the other's
file goes stale. `snort_pcap_pipeline.sh` intentionally omits `-A fast`,
relying solely on the config's bare `output alert_fast` directive.

**Self-generated traffic doesn't prove real-attack detection.** Sending
traffic to the host's own IP (from Windows or from WSL) is routed
internally via loopback on any OS before it reaches a physical capture
point, so it won't appear in the pcap captures no matter how the pipeline
is configured - this is normal OS behaviour, not a bug. Test with traffic
from a genuinely separate device instead.

---

## Running Snort on Windows

Windows has no Unix domain sockets, so `unixsock` is not available there.
Use the `file` transport instead: Snort writes `alert_fast` lines to a text
file, and AETHRA-SEC tails it.

> **Known issue:** as of Snort 2.9.20, the official Windows x64 installer's
> `snort.exe` cannot start on current Windows 10/11 — see the WSL section
> above, which is the working path. This section is kept for reference.

### 1. Install Snort

Snort 2.9 for Windows and Npcap (packet capture driver, required) are
downloaded from https://www.snort.org/downloads — grab the latest Snort 2.9.x
Windows installer and the matching Npcap installer, then run both. The
default install path is `C:\Snort`.

Confirm it installed:

```powershell
& "C:\Snort\bin\snort.exe" -V
```

### 2. Install this configuration

Copy the Windows config, local rules, and Snort's own reference files into
`C:\Snort\etc`:

```powershell
Copy-Item snort.windows.conf "C:\Snort\etc\snort.conf"
Copy-Item local.rules "C:\Snort\etc\local.rules"
```

`classification.config` and `reference.config` ship with the Snort
installer under `C:\Snort\etc`; `snort.windows.conf` includes them from
there. Validate the config:

```powershell
& "C:\Snort\bin\snort.exe" -c "C:\Snort\etc\snort.conf" -T
```

`local.rules` holds three deliberately broad rules (ICMP echo, TCP SYN, UDP
to port 53) to prove the ingest path end to end on a lab network; replace
them with a rule set suited to a real network, since rules this broad will
alert on ordinary traffic.

### 3. Point AETHRA-SEC at the alert file

In `.env`:

```ini
AETHRA_SNORT_TRANSPORT=file
AETHRA_SNORT_ALERT_FILE=C:\Snort\log\alert.ids
AETHRA_SNORT_PATH=C:\Snort\bin\snort.exe
AETHRA_SNORT_CONFIG=C:\Snort\etc\snort.conf
```

### 4. Start Snort first, then AETHRA-SEC's ingest

Unlike `unixsock`, the socket direction is reversed: here it's AETHRA-SEC
that expects the file to already exist when it opens it for tailing — if
`AETHRA_SNORT_ALERT_FILE` isn't there yet, ingest reports "Snort
unavailable" instead of waiting for it. So start Snort first, so it
creates `alert.ids`, then start (or restart) AETHRA-SEC.

Find your capture interface number, then start Snort as Administrator:

```powershell
& "C:\Snort\bin\snort.exe" -W                                   # list interfaces
& "C:\Snort\bin\snort.exe" -c "C:\Snort\etc\snort.conf" -i <N> `
    -l "C:\Snort\log" -A fast
```

Then start AETHRA-SEC (or, if it's already running, use the Settings
screen's Snort restart action so it opens the now-existing file). The
Alerts screen then shows `RUNNING · transport: file`, and its counters
(received / stored / duplicates folded / parse failures) are live.

### Windows troubleshooting

**Nothing shows up.** Confirm `C:\Snort\log\alert.ids` is actually growing
while traffic flows on the chosen interface (`Get-Content -Wait
C:\Snort\log\alert.ids` in a separate PowerShell window). If the file never
grows, Snort likely started on the wrong interface, or Npcap did not
install correctly (`snort -W` should list at least one usable interface).

**Access denied / can't open the interface.** Run the Snort PowerShell
window as Administrator — packet capture requires elevation on Windows.

**AETHRA-SEC still says "Snort unavailable".** Check `AETHRA_SNORT_TRANSPORT`
is `file` (not `disabled`) and `AETHRA_SNORT_ALERT_FILE` matches the `-l`
directory plus the `output alert_fast:` filename exactly, then restart
AETHRA-SEC (or use the Settings screen's Snort restart action) so it
re-reads `.env`.
