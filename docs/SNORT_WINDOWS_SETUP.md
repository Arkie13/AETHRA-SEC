# Snort on Windows, step by step

AETHRA-SEC does not launch Snort and does not bundle it. Snort runs as its own
process, writes alerts, and AETHRA-SEC reads them. This guide gets that working
on Windows from nothing.

**Windows cannot use the `unixsock` transport.** It relies on Unix domain
sockets, which Windows does not have — the transport refuses to start and says
so. On Windows you use the **alert file** transport: Snort appends alerts to a
text file and AETHRA-SEC tails it. That is the path this guide sets up, and it
is the one verified against a real sensor.

Everything below needs an **Administrator** command prompt. Packet capture is a
privileged operation.

---

## Step 1 — Install Npcap

Snort cannot see traffic without a capture driver.

1. Go to <https://npcap.com> and download the Npcap installer.
2. Run it as Administrator.
3. **Tick "Install Npcap in WinPcap API-compatible Mode".** Snort 2.9 is built
   against the WinPcap API; without this box Snort installs fine and then finds
   no interfaces at all.

If you already run Wireshark, Npcap is probably installed — but check that
WinPcap compatibility was enabled, because Wireshark does not require it.

## Step 2 — Install Snort

1. Go to <https://www.snort.org/downloads> and open the **Snort 2.9.x** section.
2. Download **`Snort_2_9_20_Installer.x64.exe`** — the last Windows installer
   Snort published (2.9.20, June 2022).
3. Run it as Administrator and accept the default location, `C:\Snort`.

**Use 2.9.20 even though 3.x exists.** Snort 3 is the actively maintained
branch, but it ships **no official Windows binaries** — Windows is still an
open roadmap item, and the project's own advice for Windows users is WSL.
2.9.20 is legacy and will not gain new features, which is a real limitation to
know about; it is also the only Snort that installs on Windows as a binary.

You should end up with `C:\Snort\bin`, `C:\Snort\etc`, `C:\Snort\log` and
`C:\Snort\rules`.

Check it runs:

```bat
C:\Snort\bin\snort.exe -V
```

You should see the Snort banner and a version. If Windows says the command is
not found, use the full path or add `C:\Snort\bin` to `PATH`.

> **If the download is unavailable to you.** The alternative is to run
> AETHRA-SEC and Snort together inside WSL, where `apt-get install snort`
> works, a current Snort is available, and the faster `unixsock` transport can
> be used instead of tailing a file. Ask and I will write that variant up.

## Step 3 — Find your interface number

Windows Snort selects interfaces by **index**, not by name:

```bat
C:\Snort\bin\snort.exe -W
```

You will get a numbered list with descriptions and addresses. Note the index of
the adapter carrying the traffic you want to monitor — usually your Wi-Fi or
Ethernet adapter. Call it `N` below.

If the list is empty, Npcap is missing or was installed without WinPcap
compatibility. Go back to step 1.

## Step 4 — Install the configuration and rules

The stock Windows `snort.conf` ships with dozens of Linux paths and needs heavy
editing. Rather than fight it, use the minimal pair shipped with AETHRA-SEC.

**Copy them into place** rather than retyping them. From the AETHRA-SEC folder
in an Administrator prompt:

```bat
copy /Y deploy\snort\windows\aethra.conf  C:\Snort\etc\
copy /Y deploy\snort\windows\local.rules  C:\Snort\rules\
```

Typing these by hand in Notepad is the usual source of trouble: Explorer hides
extensions, so `aethra.conf` quietly becomes `aethra.conf.txt` and Snort
reports a file it cannot find.

Both files were validated against real Snort 2.9.20 — see *What was verified*
at the end of this guide. Their contents are reproduced below for reference.

`C:\Snort\etc\aethra.conf`:

```
# Minimal Snort 2.9 configuration for AETHRA-SEC on Windows.
config logdir: C:\Snort\log
config checksum_mode: none

dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor
dynamicengine C:\Snort\lib\snort_dynamicengine\sf_engine.dll

preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp yes
preprocessor stream5_tcp: policy first
preprocessor stream5_udp
preprocessor stream5_icmp

include C:\Snort\etc\classification.config
include C:\Snort\etc\reference.config

# Alerts are written to C:\Snort\log\alert.ids, which is what AETHRA-SEC tails.
output alert_fast: alert.ids

include C:\Snort\rules\local.rules
```

Check the two `dynamic...` paths actually exist under `C:\Snort\lib` — the
folder names vary slightly between installers. If they are absent, delete those
two lines; the configuration below does not depend on them.

## Step 5 — The rules

Step 4 already copied these in. For reference, `C:\Snort\rules\local.rules`
contains:

```
alert icmp any any -> any any (msg:"ICMP echo request"; itype:8; sid:1000001; rev:1; classtype:misc-activity;)
alert tcp any any -> any any (msg:"TCP SYN to HTTP port"; flags:S; dsize:0; sid:1000002; rev:1; classtype:attempted-recon;)
alert udp any any -> any 53 (msg:"UDP traffic to DNS port"; sid:1000003; rev:1; classtype:misc-activity;)
```

These are the same three rules used to verify the pipeline here. They are
**deliberately broad** — they fire on ordinary traffic, which is what makes them
useful for proving the plumbing works in one minute rather than waiting for a
real attack.

**Replace them before you rely on this for monitoring.** Broad rules on a real
network produce constant alerts and train you to ignore the screen. Snort's
registered and community rule sets are on snort.org; download one, unpack it to
`C:\Snort\rules`, and `include` the files you want in `aethra.conf`.

## Step 6 — Validate the configuration

```bat
C:\Snort\bin\snort.exe -c C:\Snort\etc\aethra.conf -T -i N
```

Success ends with **"Snort successfully validated the configuration!"**. Fix
anything it complains about here — Snort reports the offending file and line,
and a config that fails `-T` will never run.

## Step 7 — Point AETHRA-SEC at the alert file

Open `.env` in the AETHRA-SEC folder (copy `.env.example` to `.env` if you have
not already) and set:

```ini
AETHRA_SNORT_TRANSPORT=file
AETHRA_SNORT_ALERT_FILE=C:\Snort\log\alert.ids
AETHRA_SNORT_PATH=C:\Snort\bin\snort.exe
AETHRA_SNORT_CONFIG=C:\Snort\etc\aethra.conf
```

`.env` is read once at startup, so restart AETHRA-SEC after editing it.

The last two keys are not used for ingest — they let the System Health screen
report the sensor's version and configuration.

## Step 8 — Start them, Snort first

**Order matters for the file transport.** AETHRA-SEC tails the alert file, so
the file has to exist when it starts; otherwise the ingest reports the file is
missing.

In an Administrator prompt:

```bat
C:\Snort\bin\snort.exe -c C:\Snort\etc\aethra.conf -i N -A fast -l C:\Snort\log
```

Leave it running. Then start AETHRA-SEC (`run.bat`) in a second window.

> If you would rather start them in either order, create the file once with
> `type nul > C:\Snort\log\alert.ids`. AETHRA-SEC will then attach and wait.

## Step 9 — Confirm it works

In AETHRA-SEC:

- the header chip reads **SNORT RUNNING** instead of SNORT DISABLED;
- **Alerts** shows `RUNNING · transport: file · C:\Snort\log\alert.ids`;
- the counters — received, stored, duplicates folded, parse failures — are live.

Generate something the rules will catch. From any prompt:

```bat
ping 127.0.0.1
```

Within a few seconds the ICMP rule should fire and the alert should appear on
the Alerts screen without you refreshing anything.

---

## Troubleshooting

**Header still says SNORT DISABLED.** `.env` was not read. Confirm the file is
named exactly `.env` (Explorer hides extensions — `.env.txt` is the usual
culprit), that `AETHRA_SNORT_TRANSPORT=file` has no typo, and that you restarted
the application.

**"the alert file does not exist yet".** Snort has not written it. Snort only
creates the file on its *first alert*, so if nothing has matched yet the file is
genuinely absent — trigger a ping, or create the file as shown in step 8.

**Snort exits immediately.** Run it without `-q` to see the error. The usual
causes are a bad interface index, a path in `aethra.conf` that does not exist,
or not being Administrator.

**Snort runs but never alerts.** Check you are on the right interface — `-W`
descriptions can be misleading on machines with several adapters, and loopback
traffic is not visible on a physical adapter. Try each candidate index.

**Alerts received but the stored count barely moves.** That is deduplication,
not loss. A flood matching one rule folds into a single row whose
`duplicates folded` counter climbs; the Alerts screen shows both numbers.

**Alerts appear with no signature shown.** Snort is writing a format the parser
does not recognise. Use `-A fast`, which is what this guide configures.

---

## What was verified, and where

**The configuration and rules in `deploy/snort/windows/` were run through real
Snort 2.9.20** — the same version the Windows installer provides. With the
paths translated to a Linux layout and the two `dynamic...` lines removed (they
are Windows-specific), Snort reported *"Snort successfully validated the
configuration!"*, loaded the three rules, matched a real TCP SYN on the wire,
and wrote:

```
08/22-19:13:51.456750  [**] [1:1000002:1] TCP SYN to HTTP port [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 127.0.0.1:35370 -> 127.0.0.1:3306
```

That line was then fed to AETHRA-SEC's own `parse_fast`, which recovered every
field: generator 1, signature 1000002, revision 1, classification "Attempted
Information Leak", priority 2, protocol TCP, and both endpoints with ports.

So the config syntax, the rule syntax, the `alert_fast` output format and the
ingest parser are all confirmed against the real tool rather than assumed.

The earlier end-to-end sensor test — Snort writing alerts, AETHRA-SEC tailing
and storing them — recorded 11 alerts received with 0 parse failures.

That testing was done on Linux, because this development machine is Linux. The
ingest code, the parser and the alert format are identical on Windows; what is
untested here is the Windows-specific half — the installer, Npcap and the
interface indexing in steps 1 to 6. Those steps follow Snort's documented
Windows behaviour, but if one of them does not match what you see, tell me what
Snort printed and I will correct this guide.
