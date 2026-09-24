# UI screen map

Tkinter/ttk desktop console. One window: a header, a grouped left sidebar, the
active screen, and a status bar. Sidebar entries the signed-in role cannot use
are not rendered — the interface never offers an action the service layer would
refuse.

## The shell

**Header.** A collapse control, an accent mark and a two-line wordmark
(*AETHRA-SEC* over *SECURITY OPERATIONS CONSOLE*); then a real search field —
not a button that opens one — carrying its own `Ctrl+K` badge, which hands
whatever has been typed straight to the command palette rather than making the
operator type it twice; then the clock, the signed-in username with its role
badge beneath it, the notification bell and *Sign out*, separated by hairline
dividers. A second band underneath carries the live subsystem chips, labelled
`SUBSYSTEMS`, each one showing the state its probe actually returned.

**Panels.** Every card is a bordered panel: a one-pixel edge so its bounds are
findable on a dark ground, an accent tick and an upper-cased title on a header
band, and a rule under the header so the title is not read as the first line of
content. Stat tiles carry their severity as a full-height edge on the left, so
a row of tiles can be read at a glance from across a room.

**Rows of controls never clip.** Actions above a table, a screen's filter
fields, and a table's own footer are all laid out by one wrapping bar: when the
window is too narrow the controls that do not fit move onto a second line, a
caption travels with the field it names, and a control pinned to the right — a
record count — is measured before the rest so it is never the thing squeezed
out. A keyboard hint may be dropped to save the data beside it; data never is.

Every screen refreshes from the event bus, drained on the Tk `after()` tick
(`ui.refresh_interval_ms`, default 2000 ms). Long work runs on a worker thread
via `Screen.run_async`, so the interface never freezes during a scan, an export
or a query; while one is in flight the status bar shows an activity marker.

**Empty states are real.** Where there are no records, a screen says
*"No data available"* or *"Waiting for live network data..."*. No screen shows
a placeholder value, no indicator shows "running" unless the subsystem answered
a probe, and no trend arrow appears unless a comparable earlier period is
actually stored.

**Severity is never colour alone.** Every severity carries a distinct shape —
◆ critical, ▲ high, ■ medium, ● low, ○ informational — so the tables stay
readable without relying on red-versus-orange.

---

## Navigation

The sidebar is grouped by what the operator is doing, under upper-cased group
headings. Each entry's glyph sits in a fixed-width cell of its own, so the
labels align down the column and the glyph stays in place when the sidebar is
collapsed to a rail (Ctrl+B); the glyph is clickable and tooltipped in both
states. The current page carries an accent bar as well as a filled row, the
collapse animates rather than jumping, and the entries scroll when a short
window cannot hold all of them - navigation is never pushed out of reach.
Alerts, Incidents and Users carry a live count badge, drawn from stored
records; a badge is absent when the count is zero.

Groups follow the order of an investigation: what is happening, what has
been found, what it happened to — then the two groups nobody opens mid-incident.

| Group | Order | Screen | Permission | Available to |
| --- | --: | --- | --- | --- |
| Monitor | 1 | Dashboard | `dashboard.view` | ADMIN, USER |
| Monitor | 2 | Live Monitoring | `monitor.view` | ADMIN, USER |
| Security | 3 | Incidents *(badge: incidents nobody has opened yet)* | `incident.view` | ADMIN, USER |
| Security | 4 | Alerts *(badge: unreviewed alerts)* | `alert.view` | ADMIN, USER |
| Security | 5 | Mitigation | `mitigation.view` | ADMIN, USER |
| Assets | 6 | Hosts | `host.view` | ADMIN, USER |
| Assets | 7 | Vulnerabilities | `scan.view` | ADMIN, USER |
| Reporting | 8 | Reports | `report.generate` | ADMIN, USER |
| Reporting | 9 | Logs & Audit | `log.view` | ADMIN |
| Administration | 10 | Users *(badge: recovery requests awaiting review)* | `user.manage` | ADMIN |
| Administration | 11 | System Health | `health.view` | ADMIN, USER |
| Administration | 12 | Settings | `settings.manage` | ADMIN |
| Help | 13 | Help | — | everyone |
| Help | 14 | About | — | everyone |

### Keyboard

| Shortcut | Action |
| --- | --- |
| `Ctrl+K` | Command palette — fuzzy search over every screen and shell action |
| `Ctrl+1` … `Ctrl+9` | Jump to the nth navigation entry |
| `Ctrl+B` | Collapse the sidebar to an icon rail, or expand it |
| `F5` / `Ctrl+R` | Reload the visible screen from the database |
| `Ctrl+N` | Open the notification panel |
| `Esc` | Close the palette or notification panel |

The command palette is built from the same permission-filtered list as the
sidebar, so it can never reach a screen the sidebar hides.

It also **searches real records**. Type two characters or more and, after a
short pause, it queries the existing host, incident and alert services and lists
what they return - an address, a reference, a signature - each entry opening the
screen that owns it. Every source is permission-checked separately, so the
palette surfaces only records this role may read, and a source that fails simply
contributes nothing rather than emptying the list. Screens rank above records,
so "open Hosts" is never buried under thirty addresses.

### Tables

Every record grid shares the same behaviour:

* click a heading to sort (the arrow shows which column and direction);
* a **quick filter** above the grid narrows it as you type, and composes with
  the screen's own filters rather than replacing them; `Esc` clears it;
* a **Columns** picker chooses what is drawn - hiding a column never discards
  its data, and exports still carry every field;
* hover highlights the row under the pointer, and rows are zebra-striped;
* **critical and high rows carry a tinted band** as well as coloured text, so
  the rows worth opening are findable without reading a word. Nothing below
  high is banded — a band on most of the rows would be a band on none of them;
* double-click opens the record's detail where the screen has one;
* right-click opens that screen's actions for the row under the pointer;
* arrow keys move the selection, `Home` and `End` jump to the ends of the queue,
  and `Shift+F10` opens the row menu without a pointer;
* `Ctrl+C` copies the selected rows as tab-separated text, `Ctrl+A` selects all;
* the footer states *"Showing X of Y record(s)"*, and says plainly when older
  rows have been dropped from a capped live view — the database keeps them.

### Summary strips

Incidents, Alerts and Hosts each open with a row of counts above the queue: a
table answers *"what are the records?"*, and this answers *"how bad is it?"*,
which is the question an operator arrives with. It is one component used by all
three, so the answer looks the same on each. Every figure is counted from the
rows the current filters returned — the strip and the table can never disagree
— and a figure that is genuinely unknown shows a dash rather than a zero.

### Details drawer

Where the question is *"what is this row?"* mid-investigation, a panel slides in
from the right rather than navigating away: an incident's affected device, a
host in the inventory, a host inside an assessment result. It shows the record's
identity, its ports, its findings and the incidents and alerts that involve it,
and it carries the full screen as a footer action for when the trail leads
there. It closes on ✕, on `Esc`, or on a click anywhere on the page behind it -
which is left visible and untouched throughout.

A drawer is used where it saves an analyst their place, not everywhere; working
a queue is still a full screen.

### Loading and feedback

Work a screen starts runs on a worker thread, so nothing blocks. While it is in
flight the status bar shows an activity marker and a hairline progress bar
appears across the top of that screen - the page waiting is the page that says
so. Completed actions post a status line or a toast; failures show the real,
actionable message.

### Charts

Hovering a time series draws a crosshair with the exact time and value at that
sample; hovering a bar or a donut legend entry highlights it and shows its share.
Clicking a top-talker bar or a severity slice opens the matching records on the
relevant screen. Readouts are drawn from the plotted values, so a hover can
never show a figure the chart was not given.

### Notifications

The bell carries an unread count and opens a panel of stored notifications,
newest first, each with its level, message and time. Real events also raise a
toast in the corner: a completed or failed assessment, a capture error, a
correlated incident, a subsystem failure. Clicking a toast opens the screen that
owns the event. Nothing schedules a decorative toast.

---

## Login window

> **Sign out returns here, it does not exit.** Choosing *Sign out* from
> the header stops live capture, ends the session, and brings this
> window back so another operator can sign in on the same running
> process. The database pool and background services stay up, so
> switching accounts is instant. Closing the window (the X, or the
> *Stop and exit* prompt) quits the application entirely.


Username, password, and — when `AETHRA_OTP_ENABLED=true` — the emailed code.
Below the form, the true state of the database and of each external tool is
shown before anyone signs in, so a misconfigured installation is obvious
immediately.

A wrong password and an unknown username produce the **same** message. A locked
account is told that it is locked and to wait out the lockout period or contact
an administrator.

### Forgot password

Two controls under *Sign in* open the recovery dialog:

| Control | Tab it opens | What it does |
| --- | --- | --- |
| **Forgot password?** | *1. Request review* | Username, an optional reason and an optional contact address. Submitting queues a request for an administrator. **No password changes.** |
| **I have a recovery code** | *2. Set a new password* | Username, the one-time code an administrator issued, and the new password twice |

The acknowledgement is identical whether or not the account exists, so the form
cannot be used to find valid usernames. The dialog states plainly that the
password is unchanged until an administrator approves and the code is used, and
it clears the code and password fields when it closes.

Empty state: nothing to show — this dialog never reports the state of a request,
because doing so would confirm the account exists. The administrator tells the
operator the outcome.

---

## 1. Dashboard

The page is divided into four named zones, in the order an operator reads them,
each introduced by an accent tick, a heading and a one-line note:

| Zone | What it holds |
| --- | --- |
| `SECURITY OVERVIEW` | the six headline tiles — posture across the selected window |
| `LIVE MONITORING` | the full-width traffic chart and the detection charts |
| `SECURITY EVENTS` | recent alerts, open incidents and the activity timeline |
| `SYSTEM STATUS` | the six subsystem probes, gridded across the page |

A **time range** control (`15m` / `1h` / `6h` / `24h` / `7d`) sits above the
tiles. It is not a display filter: the chosen window is passed to the same
`DashboardService.snapshot(window_hours=...)` query the page already used, so
every tile, chart and rollup below is recomputed over it. A range the stored
aggregates cannot reach back into is disabled rather than drawn empty, and the
note beside the control says which window is showing.

Headline tiles and charts, all fed from stored records and live counters:
network traffic, active hosts, open ports, IDS alerts today, open incidents,
open findings, alert severity split, protocol mix, recent activity, and
monitoring uptime. Each subsystem tile shows the state its probe actually
returned.

Every tile is clickable and opens the screen that owns the number, carries a
tooltip explaining exactly what it counts, and widens its accent edge once when
its value actually changes - so a figure that moved is noticed on a wall display
without having to remember the previous one. The six tiles reflow onto a second
line on a narrow window rather than clipping. The packet
and alert tiles carry a sparkline of the stored series behind them and a trend
against the equivalent span of the previous day — shown only when the database
holds aggregates reaching that far back, and otherwise left blank.

*Empty state*: "No packets captured yet", "No Snort alerts received", "No
vulnerabilities recorded", "No recorded activity" — and every number reads 0 on
a fresh installation.

---

## 2. Live Monitoring — `monitor.view` (+ `monitor.control` to start/stop)

### Behaviour under a flood

An attack is input to a monitoring system, not a reason for one to stop, so the
live view is built to stay responsive while the packet rate is not under
anyone's control:

* **The display filter is applied before packets reach the screen.** The
  capture service's packet view evaluates it on its own thread, so a flood of
  traffic nobody asked to see costs the interface nothing, and changing the
  filter re-evaluates the packets already retained without touching capture.
* **Table writes are coalesced** onto a fixed cadence (250 ms) rather than
  drawn per batch, so the cost of displaying a flood is bounded by the clock
  instead of by the sender.
* **Appending costs the rows appended**, not the rows already held. This is the
  difference between keeping up and never catching up: the table used to redraw
  itself completely on every batch, which at a 2,000-row cap cost ~37 ms of
  interface time per write.
* **The display buffer is bounded** (5,000 packets) and drops oldest.

None of this reduces what is monitored. Packets that are filtered out of the
view, dropped from the display buffer, or aged out of the table are still
decoded, analysed by every detection rule, counted in the aggregates and
written to the database — and the screen says so, stating the arrival rate and
what it is not showing rather than going quiet.

Capture strip: interface selector, **CAPTURE FILTER (BPF)** (applied by dumpcap
before capture; changing it restarts capture), **Start capture** /
**Stop capture**.

Display filter bar (never restarts capture):

* presets **All Traffic, Incoming, Outgoing, Transit** and **HTTP, HTTPS/TLS,
  Web, Sites, TCP, UDP, ICMP, DNS, ARP** (a direction and a protocol combine;
  pressing the active protocol again clears it), and **Clear Filter**.
  **Sites** lists the names this computer connected to or looked up - HTTPS
  server names (SNI), HTTP Host headers and DNS queries - never page content;
* a **DISPLAY FILTER** expression (a validated Wireshark-style subset; an
  invalid expression shows **INVALID FILTER** with the reason and the previous
  filter stays active), plus **IP** and **PORT** searches scoped to source,
  destination or either;
* an **ACTIVE FILTER** line, and a counts line: **CAPTURED** (never reset by a
  filter change), **DISPLAYED** (matched), **LISTED** (rows in the table),
  totals per direction, and totals per protocol for the matched packets;
* **Pause display**, **Clear display**, **Export view**.

Live packet table (time, source, destination, protocol, src port, dst port,
length, direction, info), a packet detail panel for the selected row (HTTP
request and response fields, TLS handshake, SNI and versions, TCP flags and
sequence numbers, ARP sender and target, DNS query; N/A where the frame does
not carry the field), per-second traffic charts, protocol split, top talkers
and top destination ports.

Empty states name what was asked for: "No HTTP traffic captured.", "No
HTTPS/TLS traffic captured.", "No incoming traffic captured.". An empty Transit
view, or an IP search for another device that finds nothing, adds "Traffic is
not visible from the current capture interface." with the reason.

The capture indicator reads **"Capture NOT STARTED"** until TShark is actually
running. When the ingest queue is saturated the dropped-packet count is shown
rather than hidden — a dropped packet is a fact about the capture, not an error
to conceal.

*Empty state*: "Waiting for live network data...".

---

## 3. Vulnerability Assessment — `scan.view` (+ `scan.run` / `scan.stop`)

Target, profile, port specification, timing template, **Start scan** /
**Stop scan**. Results tab (hosts, ports, services, versions), findings with
their risk level and rationale, **Finding detail**, **Mitigation**,
**Export findings**, and a history tab with **Compare selected with previous**.

Seven profiles are offered; the two needing raw sockets are hidden when the
process is unprivileged. A target outside `AETHRA_AUTHORIZED_NETWORKS` is
refused with the offending addresses named, and the refusal is audited.

Findings state what Nmap observed. Where no configured knowledge source
matched, the finding says further verification is required rather than naming a
weakness that was not established.

### Open ports

The results tab is a vertical split: discovered hosts above, and below them a
horizontal split of **Open ports** and **Security findings**. Both dividers can
be dragged. (They are splits rather than stacked panels because two panels
that each asked for more height than the window had left the ports table
clipped to a sliver — the count of open ports was readable while the ports
themselves were not.)

Selecting a host fills the ports panel; the first host is selected
automatically, so a single-host scan shows its ports without being asked.
The panel header names the host and the count — *"192.168.1.14 · 6 open of
1000 port(s) recorded"* — and the scan summary lists the open ports inline
as well as counting them.

| Column | Source |
| --- | --- |
| Port / Proto / State | Nmap's port element, verbatim |
| Service | Nmap's service name, or `unknown` |
| Version | product and version, or `no version detected` on an open port |
| Risk | the risk level of the finding derived from **that** port |
| Finding | that finding's title, or `no finding raised` |

Where several findings share a port the most serious is shown, because that is
the one that decides whether the port needs attention. A port with no finding
says so rather than borrowing a neighbour's risk — an open port is not
automatically a vulnerability.

**Open ports only** is on by default; clearing it shows every port the scan
recorded, including closed and filtered. **Port detail** (or double-click, or
Enter) opens the port in the drawer with its reason, CPE, tunnel and the full
finding rationale. **View open ports** on a host's right-click menu jumps
straight there with the keyboard on the list.

*Empty state*: "No scan selected." / "Select a host to see the ports this scan
found" / no findings recorded.

---

## 4. Hosts — `host.view` (+ `host.manage`)

Search, risk filter, "Trusted assets only". Host table with detail panel:
addresses, OS, open ports, traffic counters, findings and alerts for that host.
Actions: **Scan this host**, **Resolve hostnames**, **Mark trusted** /
**Remove trust** (administrator), **Export**.

Hosts appear only when Nmap discovered them or live capture observed them; the
discovery source is recorded and shown.

### Hostname and operating system

Neither is a property of a packet. Capture reads an address and a MAC off the
wire; a hostname needs a reverse DNS lookup and an operating system needs an
Nmap fingerprint. An inventory that live capture built therefore has neither
until something goes and asks — so the cells say which state they are in
rather than showing a dash that could mean anything:

| Cell shows | Means | Fills in when |
| --- | --- | --- |
| `not resolved` | no reverse DNS lookup has been made | **Resolve hostnames** |
| `no DNS record` | a lookup was made and the address has no name | — nothing to fill in |
| `not scanned` | no assessment has fingerprinted this host | **Scan this host**, with the *OS detection* profile |

**Resolve hostnames** works on a batch, because a capture-built inventory of
ninety hosts is not a per-row job. With rows selected it resolves those; with
nothing selected it resolves every host nobody has looked up yet, after saying
how many DNS queries that will be. Lookups run concurrently and are capped per
round. A lookup that returns nothing stores nothing — a hostname is never
invented for an address that has none (§15) — but the *attempt* is recorded, so
a nameless address is asked once rather than on every pass.

An optional background resolver (`hosts.auto_resolve_hostnames`, **off** by
default) does the same for newly observed hosts on an interval. It is opt-in
because every lookup is a DNS query, which an operator monitoring a network
should be choosing to generate rather than discovering after the fact.

An OS is only ever written by an assessment that actually fingerprinted the
host, and is stored with the accuracy Nmap reported: `Linux 5.0 - 5.7 (100%)`.
Nothing is inferred from the MAC address or from the traffic.

---

## 5. Alerts — `alert.view` (+ `alert.manage`, `evaluation.classify`)

Search, severity/status filters, **Apply** / **Reset**. Alert table with
**Details**, **Mark reviewed**, **Escalate** (creates or opens an incident),
**Open incident**, **Export**.

Each alert shows both timestamps (sensor time and received time), the signature
identifiers, the transport it arrived on, the folded duplicate count, and the
raw alert text as retained evidence. Analysts classify true/false positive —
AETHRA-SEC never labels a detection automatically.

*Empty state*: the sensor's own status text, e.g. "Snort unavailable".

---

## 6. Incidents — `incident.view` (+ `incident.manage`)

Search and filters, then the investigation view across five tabs.

**Summary & risk** is laid out rather than dumped: the reference with severity,
status and category chips, the confidence and evidence provenance, the incident
facts as a labelled grid — including the **attacker/source address** — then
**Devices involved**, then what was observed, and the **transparent severity
calculation** drawn as bars — one row per stored scoring factor, with the points
it contributed and the recorded reason, plus the thresholds each level maps to.
The bars are re-read from the rationale the risk engine wrote when the incident
was scored, so the number can be audited rather than trusted.

**Devices involved** lists every address this incident's own evidence names -
an incident records one affected host, but its alerts, anomalies and findings
routinely span several devices. Each row gives the role it played (source,
target, or both), the address, and whatever the host inventory knows about it:
hostname, MAC, operating system, status, risk and trust. An address the
inventory has never seen is still listed, with dashes rather than a guess.
Double-click a row to open it in the host inventory.

**Evidence**, **Timeline**, **Mitigation** and **Notes & audit** carry the
contributing Snort alerts, traffic anomalies and Nmap findings, a chronological
timeline built from real timestamps, the mitigation guidance, and analyst notes.

Actions: **Assign to me**, **Add note**, status changes, **Export**, and a
right-click menu on any row — *Mark investigating*, *Acknowledge*, *Resolve*,
*Mark false positive*, *Assign to me*, *Add note*, *Open affected host*,
*Copy ID*. The menu acts on the row that was right-clicked, not on whatever was
selected beforehand.

Opening an incident marks it read, which is what the sidebar badge counts: the
number nobody has looked at yet, not everything that happens to be open. The
read state is stored, so it survives a restart and is shared by every operator.

The evidence provenance line is explicit: an incident supported by one
subsystem says "Snort only"; one corroborated by a scan says "Snort + Nmap".

---

## 7. Mitigation — `mitigation.view` (+ `mitigation.manage`)

Search, category filter, "Active only". Each entry: what the threat is, why it
matters, the immediate action, the longer-term action, verification steps and
reference notes. Administrators get **New recommendation**, **Edit**,
**Activate**/deactivate.

The screen states plainly that AETHRA-SEC applies nothing — the guidance is for
an authorised human to act on.

---

## 8. Reports — `report.generate` (+ `report.export`)

Report type, period, scope, **Preview**, then export to CSV, Excel or PDF.

Eight report types: Security Assessment, Vulnerability, Network Monitoring, IDS
Alert, Threat Incident, Mitigation, System Activity, Executive Summary.

**Preview shows the record count for every section before anything is
written**, so an operator sees an empty report as empty rather than discovering
it after exporting. Reports carry metadata — who generated it, when, over what
period, the total record count and the authorised-use notice — and a section
with no rows prints "No records available for this section in the selected
period."

---

## 9. Logs & Audit — `log.view` (+ `log.export`, `log.verify`)

Three tabs: **Audit trail**, **System errors**, **Application log**. Search,
filters, **Record detail**, **Acknowledge** (errors), **Export**, **Reload**,
and integrity verification.

A failed verification is shown as `LOG INTEGRITY WARNING`, naming the records
involved and whether the problem is content, chain or ordering. It is never
silently corrected.

---

## 10. Users — `user.manage` (administrator only)

Tabs: **Accounts**, **Password recovery**, **Sign-in history**, **Active
sessions**, **Roles & permissions**. The header card states the account counts
and, in amber, how many recovery requests are waiting; the sidebar entry carries
the same count as a badge, and shows none when the queue is empty.

**Accounts** — **Create account**, **Edit**, **Reset password**,
**Activate**/**Deactivate**, **Unlock**, **Force sign-out**.

*Create account* asks for the username, full name, email, role and an initial
password, and whether a change is required at first sign-in. Leaving the
password blank generates a strong one. The credentials are shown **once**, in a
monospaced dialog, and are not stored in readable form anywhere. A duplicate
username, an unknown role or a password that fails policy is refused with the
reason.

**Password recovery** — the queue of requests raised at the sign-in screen,
filtered by state (awaiting review, approved, rejected, completed, expired).
Actions: **Approve and issue code**, **Reject**, **Refresh**.

Approving asks how identity was confirmed — that note goes to the audit trail
with the approver's name — and then shows the one-time code once. Rejecting
revokes any code already issued. The columns lead with the fields a decision
turns on: when it was raised, which account, its state, the deadline and how
many wrong codes have been tried. The tab is replaced by an explanatory empty
state for a session that does not hold `user.reset_approve`, and the service
refuses the action regardless of what the interface shows.

Passwords are entered only in a dialog, never displayed in a table, and only
their hash is stored. The roles tab lists every permission each role holds, so
the authorisation model is visible rather than implied.

---

## 11. System Health — `health.view` (+ `health.detail`)

Live probe results for the database, Nmap, TShark, Snort, capture, scheduler,
disk, log and report directories, password hashing, two-factor status and the
mitigation knowledge base. **Run diagnostics**, **Re-probe now**, **Runtime
detail** (administrator).

Each row states what the probe found and, when something is wrong, what to do
about it. Nothing is reported healthy because it is configured.

---

## 12. Settings — `settings.manage` (administrator only)

* **Tunable settings** — the 49 database-backed settings by category
  (detection, correlation, capture, retention, hosts, backup, UI, security,
  notifications), each with its range and description. **Edit selected**.
* **Deployment configuration** — credentials, tool paths, the Snort transport
  and the authorisation boundary, shown **read-only** and redacted. These live
  in `.env`; changing a credential from inside a running application is not a
  safe operation.
* **Data maintenance** — **Run retention now**, **Prune audit log**,
  **Restart Snort ingest**, **Refresh sizes**.
* **Database backup** — see below.

Every change is validated against the setting's declared range and audited as
`SETTING_CHANGED` with the old and new values.

### Database backup

A real `mysqldump` of the live schema, written to a timestamped file that
never overwrites an existing one. The tab has three parts:

**Status** — the backup folder, the newest backup with its size and age, how
many are retained and what they occupy, and when the next automatic backup
falls due. Every figure is read from files that exist on disk; before the first
backup it says so rather than showing a zero. If `mysqldump` is not on `PATH`
the tab says that first, because nothing else on it can work without it.

**Automatic backup** — a checkbox, an interval in hours, how many files to keep
and the destination folder. The countdown is measured from the newest backup
already on disk, not from when the process started, so restarting AETHRA-SEC
does not push the next backup back and the interval means what it says: never
longer than this without a backup. The scheduler checks every minute and dumps
only when the interval has actually elapsed. It is **off until an administrator
turns it on** — a job that writes the whole database to disk is opt-in.

After a successful automatic run the oldest files beyond the keep count are
deleted. Only files AETHRA-SEC wrote are ever considered, the newest is never
removed, and a keep count of `0` keeps everything. A scheduled run that fails —
a missing tool, a full disk — is recorded in the audit trail as a failure and
raises a notification, so an operator is never left believing in a backup that
did not happen.

**Backups on disk** — the real files, newest first, with size and age.

| Action | What it does |
| --- | --- |
| **Back up now** | dumps into the configured folder |
| **Back up and save as…** | dumps straight to a file you choose, anywhere |
| **Save a copy…** | copies an existing backup out; the original stays |
| **Delete** | removes one backup file, audited, after confirmation |

Every one of these needs `data.maintain` (administrator), is checked in the
service layer rather than only in the interface, and is written to the audit
trail as `DATABASE_BACKUP`. The password reaches `mysqldump` through the
environment, never on the command line, so it cannot be read out of the process
list.

---

## 13. Help

Educational content for a Network Security laboratory: what each detection rule
measures, which setting controls its threshold, why it matters and what to
check; how risk levels are derived; and what an open port does and does not
imply.

Tabs: *Getting started*, *Accounts & access*, *Monitoring*, *Assessment*,
*Detection rules*, *Risk & correlation*, *Mitigation & reports*, *Common
errors*. **Accounts & access** covers the two roles and what each may do, how an
account is registered, and both sides of the password recovery workflow — the
operator's four steps and the administrator's review — so the person handling a
lockout has the whole procedure in front of them.

## 14. About

Application identity and version, the technology stack, the authorised-use
notice, and the runtime environment (Python version, platform, tool versions
that were actually detected).

---

## Remembered preferences

The console stores a few display preferences beside the logs, in
`ui_state.json`: the window geometry, whether the sidebar was collapsed, and the
screen that was open last. They are preferences only — the file holds no
security data and no credentials, and a missing or damaged file simply starts
the console with its defaults.
