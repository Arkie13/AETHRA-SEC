# AETHRA-SEC user guide

Day-to-day operation, in the order a shift actually happens. For installation
see [`INSTALL_WINDOWS.md`](INSTALL_WINDOWS.md); for what each screen contains
see [`UI_SCREEN_MAP.md`](UI_SCREEN_MAP.md).

> Operate AETHRA-SEC only against networks you are authorised to monitor and
> assess. It refuses targets outside `AETHRA_AUTHORIZED_NETWORKS`, but setting
> that boundary correctly is your responsibility.

---

## 1. Starting a shift

1. `python -m aethra_sec.main`, sign in.
2. **System Health** — read it before anything else. It tells you what is
   actually available: database, Nmap, TShark, Snort transport, capture
   privileges, disk. Warnings are normal (no interface selected yet, Snort
   disabled); a FAIL names what to fix.
3. **Dashboard** — the state of the network as recorded so far. On a fresh
   installation every tile reads zero. That is correct.

---

## 2. Monitoring live traffic

**Network Monitoring** → choose the interface → optionally set a BPF filter →
**Start capture**.

* The indicator changes from *"Capture NOT STARTED"* only when TShark is
  actually running.
* Packets stream into the table; select one to see its decoded layers.
* The charts show packets and bytes per second, the protocol split, top talkers
  and top destination ports, computed from the packets that actually arrived.
* **Resume display** pauses the scrolling table while capture continues — use
  it to read a row without stopping the capture.

**A monitoring port only sees the traffic that reaches it.** On a switched
network you will see your own host's traffic plus broadcast/multicast unless
the switch mirrors traffic to your port (SPAN). If the table looks quieter than
expected, that is usually why.

If the capture queue saturates, the dropped-packet count is displayed. Reduce
the load with a narrower BPF filter, or set
`capture.persist_packet_metadata = false` to keep aggregates only.

### What gets detected automatically

Six deterministic threshold rules run over the live stream. Each states the
value measured, the threshold it exceeded and the window used:

| Rule | Measures | Threshold setting |
| --- | --- | --- |
| Excessive ICMP traffic | ICMP packets per source per second | `detection.icmp_packets_per_second` |
| UDP flood indicator | UDP packets per source toward one port | `detection.udp_packets_per_second` |
| Potential TCP SYN flood | SYNs per source vs SYN/ACKs seen | `detection.tcp_syn_per_second` |
| Abnormal HTTP volume | Decoded HTTP packets per source | `detection.http_requests_per_second` |
| Port scanning behaviour | Distinct destination ports per source/target | `detection.port_scan_distinct_ports` |
| Network sweep behaviour | Distinct destination hosts per source | `detection.host_sweep_distinct_hosts` |

There is no machine learning and no behavioural model. Every detection can be
explained by arithmetic you can check, and the Help screen explains each rule
in plain language.

Note that your own authorised scan will trip the port-scan rule — that is the
rule working correctly, and the resulting anomaly names the source address.

---

## 3. Running an assessment

**Vulnerability Assessment** → target → profile → **Start scan**.

| Profile | What it does | Needs privilege |
| --- | --- | --- |
| Host discovery (ping sweep) | `-sn` | no |
| Quick port scan | top 100 ports | no |
| Standard scan | top 1000 ports + service versions | no |
| Custom port range | your validated port spec + versions | no |
| Full TCP scan | all 65535 ports | no |
| OS detection | SYN scan + versions + OS fingerprint | yes |
| Common UDP services | top 50 UDP ports | yes |

* The target is validated and checked against the authorisation boundary before
  any argument is built. A refusal names each offending address.
* The port specification accepts only digits, commas and hyphens. Anything else
  is refused — nothing you type reaches a command line as free text.
* The privileged profiles are hidden when the process cannot open raw sockets.
* The exact argument list and Nmap version used are stored with the scan.

### Hostname and operating system

A port scan answers *what is listening*, not *what is this machine*. After the
port scan finishes, every host that is up and still missing a name or an OS
gets one short follow-up probe — ports 135/139/445 with Nmap's `nbstat` and
`smb-os-discovery` scripts, plus `-O` fingerprinting where the process has
raw-socket privileges. Both scripts only read what a service volunteers;
neither authenticates and neither guesses a credential.

Answers are preferred in this order, and the source is shown next to the value
in the host's detail drawer:

| Field | Order of preference |
| --- | --- |
| Hostname | PTR record → SMB computer name → NetBIOS name → local resolver → mDNS |
| Operating system | what SMB reported → Nmap's `-O` fingerprint → scan evidence (below) |

**Scan evidence.** `-O` needs raw sockets and `smb-os-discovery` needs a host
willing to hold an anonymous SMB session, so on an ordinary unprivileged run
neither produces an answer. The scan has usually already collected one anyway,
and these sources are read directly out of Nmap's XML:

| Evidence | Confidence | Example |
| --- | --- | --- |
| An operating-system CPE reported by a service | 95% | `cpe:/o:microsoft:windows_10` |
| Nmap's service database naming the platform | 85% | `ostype="Windows"` on port 135 |
| A version banner naming the distribution | 80% | `MariaDB-0ubuntu0.24.04.1` → Ubuntu 24.04 |
| The reply TTL | 45% | 128 → Windows, 64 → Linux/Unix, 255 → network device |

The percentage shown beside the OS is that confidence, and the host's detail
drawer states the exact evidence behind it. A reply TTL narrows the *family*
only — it is never turned into a version. Software that runs everywhere
(`nginx`, a bare `MySQL` version) is not treated as evidence of anything.

The inventory keeps the **best** answer anyone has obtained rather than the
most recent one, so re-running a scan without Administrator rights will not
replace a measured fingerprint with a weaker inference.

Where nothing answers, the cell reads **Unknown** and the drawer's *Why
identity is incomplete* section says which methods were tried and what stopped
them. Two things commonly do:

* **No PTR record.** Normal on a LAN where the router hands out addresses and
  registers no names. NetBIOS, SMB and mDNS cover most such devices; a Linux
  box with none of those services running genuinely has no name to give.
* **Nothing listening.** A host with no open port offers no banner and no
  service CPE, so only the reply TTL is available — and a firewalled host that
  answers nothing at all leaves even that empty.

Running as Administrator (Windows) or root (Linux) additionally enables `-O`,
which is the only source that identifies an OS from the network stack itself
rather than from something a service said.

**Reading findings.** A finding states what Nmap observed (the port, service
and version), why it is a concern, and its risk level with the reasoning. Where
no configured knowledge source matched the service, the finding says *further
verification is required* — it does not name a CVE that was not established.
An open port is not automatically a vulnerability; it is an exposed service to
review.

---

## 4. Working alerts and incidents

**Alerts** lists what your Snort sensor produced. Each alert shows both
timestamps, the signature identifiers, the transport it arrived on, how many
duplicates were folded into it, and the raw alert as evidence.

* **Mark reviewed** when you have looked at it.
* **Escalate** to create or join an incident.
* Classify true or false positive — that judgement is yours; AETHRA-SEC never
  labels a detection automatically, and the classification is audited.

**Incidents** group related evidence. The investigation view gives you:

* the **severity calculation**, factor by factor, with the points each
  contributed and why;
* an evidence **timeline** built from real timestamps;
* the contributing alerts, anomalies and findings, each linking back to its
  source record;
* the **evidence provenance** line — "Snort only" means one subsystem saw it;
  "Snort + Nmap" means a scan finding corroborates it. Corroborated evidence
  deserves more of your attention, and the incident says so rather than hiding
  the distinction behind a single score.

Assign the incident to yourself, add notes as you investigate, and move it
through its status as you go.

---

## 5. Acting on mitigation guidance

Every incident and finding links to mitigation guidance: what the threat is,
why it matters, the immediate action, the longer-term action, and how to verify
the fix worked.

**AETHRA-SEC applies none of it.** It does not block addresses, change firewall
rules or disable services. The recommendation is for an authorised human to
evaluate and carry out through the proper change process. Administrators can
extend the knowledge base on the **Mitigation** screen.

---

## 6. Reporting

**Reports** → type → period → scope → **Preview**.

The preview shows the record count for each section *before* you export, so an
empty period is visible immediately. Export to CSV, Excel or PDF; the file lands
in `AETHRA_REPORT_DIR` (default `reports_output/`) and is recorded in the
`reports` table with its section counts.

Every report carries who generated it, when, over what period and scope, the
total record count and the authorised-use notice. A section with no rows says
so — reports never pad a period with plausible-looking numbers.

---

## 7. Administrator tasks

* **Users** — register accounts, review password recovery, reset passwords,
  unlock, force sign-out. Analysts (USER) can monitor, assess, read incidents
  and report; administrators can also change settings, manage accounts, approve
  password recovery, classify detections and read the audit trail. Changing an
  account's role signs that account out, because permissions are decided at
  sign-in.

  **Registering an operator.** *Accounts* → **Create account**. Give the
  username, name, email and role; leave the password blank to have a strong one
  generated. The credentials appear once, in a dialog — copy them out and hand
  them over through a channel you trust. Leave *Require change at next sign-in*
  ticked so the operator ends up with a password only they know.
* **Settings** — tune detection thresholds, retention, refresh rates and
  security policy. Deployment values (credentials, tool paths, transport,
  authorised networks) are read-only here and live in `.env`. Security policy
  changes apply immediately, not at the next restart.
* **Logs & Audit** — read the audit trail and run **Verify integrity**. A
  `LOG INTEGRITY WARNING` means a record was altered, deleted or inserted;
  investigate it, because the chain does not fail on its own.
* **Data maintenance** — run retention pruning, prune the audit log, back up
  the database, restart Snort ingest.

---

## 7a. A forgotten password

Nobody can reset their own password here, and AETHRA-SEC never resets one on its
own. The path runs through an administrator, and it has four steps.

**If you are the operator who forgot it:**

1. On the sign-in screen choose **Forgot password?**.
2. Enter your username, and — this is what actually helps — say why and how you
   can be reached. Send the request.
3. You will see the same acknowledgement whether or not the username was right.
   That is deliberate: the form must not tell a stranger which accounts exist.
   **Your password has not changed.**
4. An administrator will contact you, satisfy themselves that you are who you
   say, and give you a one-time code. Return to the sign-in screen, choose
   **I have a recovery code**, and set your own new password with it. Nobody
   else ever knows that password.

The code is good for one account, one use, and about an hour. Type it in any
case, with or without the hyphens. Get it wrong five times and it is revoked —
ask for a new request rather than guessing again.

**If you are the administrator:**

1. **Users → Password recovery** shows the queue; the sidebar badge counts what
   is waiting. Each row names the account, when it was raised, from which
   workstation, and the reason given.
2. **Confirm who is asking, off-system.** In person, by phone, through their
   manager — whatever your site accepts. This step is the entire security of the
   workflow; the queue only tells you what was typed into a form.
3. **Approve and issue code**. Record how you confirmed identity — that note is
   audited with your name. The code is shown to you once. Read it to the
   operator over the same channel you used to identify them, and do not paste it
   anywhere it will persist.
4. If something is wrong — the person cannot be identified, the request looks
   unexpected, the code went astray — **Reject** it. Any code already issued
   stops working at once, and the account keeps the password it had.

Every step is in the audit trail: who asked, from where, who decided, when, and
when the code was spent. The code itself is nowhere in it.

Where you would rather simply hand over a new password — onboarding, an account
whose owner has left — use **Reset password** on the *Accounts* tab instead.
That forces a change at the next sign-in.

---

## 8. Switching operators

**Sign out** (top-right) returns to the sign-in screen without closing AETHRA-SEC, so the next operator signs in on the same running process - no re-launch, no waiting for the database to reconnect. Live capture is stopped and your session is ended and audited; another operator can sign in immediately. To leave the application entirely, close the window instead.

## 8. Ending a shift

Stop the capture if nobody is watching the console, sign out (which ends the
session and is audited), and close the window. Retention pruning runs on its own
schedule; stored evidence remains for the configured periods.

---

## 9. When something looks wrong

| What you see | What it means |
| --- | --- |
| Every dashboard tile reads 0 | Nothing has been observed yet. Start a capture or run a scan |
| "Waiting for live network data..." | Capture is not running, or the interface sees no traffic |
| "Snort unavailable" | No sensor is connected on the configured transport |
| A grey capture indicator | Capture is genuinely not running — the indicator never shows green optimistically |
| Dropped packet count rising | The ingest queue is saturated; narrow the BPF filter or reduce persistence |
| A scan refused | The target is outside the authorised networks. That is the boundary working |
| `LOG INTEGRITY WARNING` | The audit chain does not verify. Treat it as a security event |
| `DATABASE OFFLINE` | MySQL is unreachable. The System Health screen has the detail |

Nothing in this list is a display bug. Each one is the application telling you
the truth about its own state.
