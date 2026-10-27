"""The manual's content. Every statement is checked against the repository.

Where a feature was removed, this says so instead of describing it. Where a
capability depends on the network rather than on AETHRA-SEC, this says that
too. Nothing here describes a button, screen or setting that does not exist.
"""

from __future__ import annotations

from reportlab.lib.units import mm
from reportlab.platypus import NextPageTemplate, PageBreak, Paragraph, Spacer
from reportlab.platypus.tableofcontents import TableOfContents

from build_user_manual import (
    APP_VERSION,
    detail,
    shot,
    step_heading,
    steps,
    S,
    bullets,
    callout,
    figure,
    h1,
    h2,
    mono,
    p,
    table,
)

W = 165 * mm


def build_story() -> list:  # noqa: PLR0915 - a manual is long by nature
    story: list = []
    add = story.extend

    # ------------------------------------------------------------------ cover
    add([
        Spacer(1, 62 * mm),
        Paragraph("AETHRA-SEC", S["coverTitle"]),
        Spacer(1, 3 * mm),
        Paragraph("Security Operations Console", S["coverSub"]),
        Spacer(1, 16 * mm),
        Paragraph("Installation and User Manual", S["coverName"]),
        Spacer(1, 4 * mm),
        Paragraph(f"Version {APP_VERSION}", S["coverSub"]),
        Spacer(1, 30 * mm),
        Paragraph(
            "A Unified System for Automated Penetration Testing with "
            "Real-Time Network Traffic Analysis and Immediate Threat "
            "Mitigation Recommender",
            S["coverSub"],
        ),
        Spacer(1, 22 * mm),
        callout(
            "important",
            "AETHRA-SEC must only be operated against networks, hosts and "
            "interfaces you are explicitly authorised to monitor or assess. "
            "It performs no exploitation, no credential attacks and no "
            "automated mitigation. All mitigation output is advisory and "
            "requires a human decision.",
        ),
        NextPageTemplate("body"),
        PageBreak(),
    ])

    # -------------------------------------------------------------------- TOC
    toc = TableOfContents()
    toc.levelStyles = [S["toc1"]]
    add([
        Paragraph("Contents", S["h1"]),
        Spacer(1, 4 * mm),
        toc,
        PageBreak(),
    ])

    # =================================================================== 1
    add(h1("About this manual"))
    add([p(
        "This manual describes AETHRA-SEC version %s as implemented in this "
        "repository. It was written by reading the application itself: the "
        "installer script, the setup wizard, the settings registry, the "
        "health service and the screen definitions. Screenshots are captures "
        "of the running application against a live database." % APP_VERSION
    )])
    add([h2("What AETHRA-SEC is")])
    add([p(
        "A Windows desktop security operations console. It captures network "
        "traffic, ingests intrusion detection alerts from a Snort sensor, "
        "runs authorised Nmap assessments, maintains a host inventory, and "
        "recommends mitigations from a local knowledge base. It records what "
        "it observes and never fabricates an observation."
    )])
    add([h2("What AETHRA-SEC does not do")])
    add(bullets([
        "It does not exploit hosts, attack credentials, or apply mitigations.",
        "It does not decrypt HTTPS. Only metadata the capture genuinely "
        "carries is displayed.",
        "It does not launch Snort. It reads alerts a sensor has written.",
        "It cannot see traffic the network does not deliver to its capture "
        "interface. Section 10 explains this in detail.",
    ]))
    add([Spacer(1, 3 * mm), table(
        ["Audience", "Start at"],
        [["Installing for the first time", "Sections 2 to 12"],
         ["Operating a working installation", "Sections 13 to 26"],
         ["Something is wrong", "Section 29, Troubleshooting"],
         ["Upgrading or removing", "Sections 27 and 28"]],
        [70 * mm, 95 * mm])])
    add([PageBreak()])

    # =================================================================== 2
    add(h1("Before you install"))
    add([p(
        "AETHRA-SEC ships as a Windows installer that contains its own Python "
        "runtime and every Python library it needs. You do not need Python, "
        "an IDE, or any development tool to run the installed application."
    )])
    add([p(
        "What you do need is the security tooling AETHRA-SEC integrates with. "
        "Those are separate products with their own licences and are "
        "installed separately. The installer reports which are already "
        "present; it does not install them for you."
    )])
    add([h2("Requirements")])
    add([table(
        ["Requirement", "Detail"],
        [["Operating system", "Windows 10 or 11, 64-bit"],
         ["Privileges", "Administrator rights to install. Live packet "
                        "capture requires an elevated process; the installed "
                        "shortcut prompts for elevation."],
         ["Disk space", "Approximately 24 MB for the installer payload, plus "
                        "room for logs, captures and reports under the data "
                        "directory. Capture files are bounded by a ring "
                        "buffer (Section 25)."],
         ["Database", "MySQL 8.0+, MariaDB 10.6+, or XAMPP, running, with an "
                      "account permitted to create a schema."],
         ["Network", "Only to reach the database and the hosts you are "
                     "authorised to assess. AETHRA-SEC does not phone home."]],
        [42 * mm, 123 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "important",
        "Being connected to the same LAN does not let a Windows laptop see "
        "every other device's traffic. If you intend to monitor devices other "
        "than this machine, read Section 10 before installing \u2014 it may "
        "change where you install AETHRA-SEC.",
    )])
    add([PageBreak()])

    # =================================================================== 3
    add(h1("Third-party dependencies"))
    add([p(
        "AETHRA-SEC detects each dependency at startup and re-checks it every "
        "time you open System Health. A missing dependency never prevents the "
        "application from starting: the affected screen reports the component "
        "as unavailable rather than implying it is working."
    )])
    add([table(
        ["Component", "Required", "Used for", "If missing"],
        [["MySQL / MariaDB", "Yes",
          "All storage: hosts, alerts, findings, audit trail",
          "The application starts with the database reported OFFLINE; nothing "
          "can be stored"],
         ["Npcap", "Yes for capture",
          "The Windows packet driver",
          "Live capture is impossible"],
         ["Wireshark / TShark", "Yes for capture",
          "Traffic analysis, driven through PyShark",
          "Live Monitoring reports TSHARK UNAVAILABLE"],
         ["Nmap", "Yes for assessment",
          "Host discovery and vulnerability assessment",
          "Assessment screens report NMAP UNAVAILABLE"],
         ["Snort", "Optional",
          "Intrusion detection alerts",
          "AETHRA-SEC's own traffic rules continue; interface reports SNORT "
          "UNAVAILABLE"]],
        [30 * mm, 21 * mm, 52 * mm, 62 * mm])])
    add([Spacer(1, 3 * mm), h2("Installing them")])
    add(bullets([
        "<b>Npcap</b> is included in the Wireshark installer. Keep that "
        "component selected; installing Wireshark covers both Npcap and "
        "TShark.",
        "<b>PyShark</b> is a Python library and is already inside the "
        "AETHRA-SEC installer. You do not install it separately.",
        "<b>Nmap</b> and <b>Snort</b> are installed from their own "
        "distributions.",
    ]))
    add([h2("How AETHRA-SEC finds them")])
    add([p(
        "Each tool is located on PATH or at its standard install location. "
        "You can override any path in the configuration file using the "
        "variables shown in Section 6. The setup wizard's <i>Security tools</i> "
        "step reports what it found, with the executable path and version it "
        "actually ran."
    )])
    add([h2("Verifying by hand")])
    add([mono(
        "nmap --version\n"
        "tshark --version\n"
        "snort -V\n"
        "mysql --version"
    )])
    add([PageBreak()])

    # =================================================================== 4
    add(h1("Installing AETHRA-SEC"))
    add([p(
        "AETHRA-SEC is installed with <b>AETHRA-SEC-Setup.exe</b>, an Inno "
        "Setup installer. The installer places the application and its runtime; "
        "it does not configure the application. Configuration happens at first "
        "launch, in the setup wizard described in Section 5."
    )])
    add([table(
        ["Step", "What happens", "What you do"],
        [["1. Elevation", "Windows asks for administrator rights.",
          "Accept. Installation writes to Program Files."],
         ["2. Existing install check", "If AETHRA-SEC is already installed the "
          "installer says so and offers to continue.",
          "Continue to upgrade in place, or cancel."],
         ["3. Licence notice", "Third-party licence information is shown.",
          "Read and accept."],
         ["4. Prerequisites", "The installer lists the security tooling and "
          "reports what is already on the machine.",
          "Note anything missing. It can be installed later."],
         ["5. Destination", "Install location, default "
          "<font face='Courier' size='7.5'>C:\\Program Files\\AETHRA-SEC</font>.",
          "Accept or choose another directory."],
         ["6. Shortcuts", "Optional Start menu and desktop icons.",
          "Select what you want."],
         ["7. Install", "Files are copied and the data directory is created "
          "with modify permission for users.", "Wait."],
         ["8. Finish", "Offers to start AETHRA-SEC immediately.",
          "Leave ticked to go straight to first-run setup."]],
        [30 * mm, 72 * mm, 63 * mm])])
    add([Spacer(1, 3 * mm), h2("Shortcuts the installer creates")])
    add([table(
        ["Shortcut", "Command", "Purpose"],
        [["AETHRA-SEC", "AETHRA-SEC.exe", "The console"],
         ["AETHRA-SEC diagnostics", "aethra-sec-cli.exe --check",
          "Runs the health check without opening the interface"],
         ["AETHRA-SEC setup", "AETHRA-SEC.exe --setup",
          "Re-runs the setup wizard"],
         ["Uninstall AETHRA-SEC", "unins000.exe", "Removal (Section 28)"]],
        [42 * mm, 58 * mm, 65 * mm])])
    add([Spacer(1, 3 * mm), h2("Installing from source instead")])
    add([p(
        "If you are working from a source checkout rather than the installer, "
        "run <font face='Courier' size='8'>setup.bat</font>. It prepares the "
        "Python environment and then hands over to the same setup code the "
        "graphical wizard runs \u2014 the same dependency probes, configuration "
        "writer, database provisioning and administrator creation. There is "
        "deliberately only one implementation. It is safe to run again."
    )])
    add([PageBreak()])

    # =================================================================== 5
    add(h1("First-run setup wizard"))
    add([p(
        "The first time AETHRA-SEC starts it runs a seven-step wizard. Nothing "
        "is written until the <i>System health check</i> step applies it, so you "
        "can move back and forth freely. You can re-run it later from the "
        "<i>AETHRA-SEC setup</i> shortcut."
    )])
    add([table(
        ["Step", "What it asks for", "Notes"],
        [["1. Administrator account", "Username, password, confirmation, email",
          "Creates the first administrator. The password is written into a "
          "hash and never stored in readable form."],
         ["2. Database", "Host, port, schema name, user, password",
          "The wizard creates the schema and applies all migrations."],
         ["3. Security tools", "Paths to Nmap, TShark and Snort",
          "Leave blank to auto-detect. The step reports what it found and the "
          "version it ran."],
         ["4. Network interface", "The capture interface",
          "Lists real adapters. Read Section 10 before choosing."],
         ["5. Email notifications", "SMTP host, port, credentials, sender",
          "Optional. Leave blank to skip; notifications remain visible in the "
          "application."],
         ["6. System health check", "Nothing \u2014 it applies and verifies",
          "Writes the configuration, provisions the database, creates the "
          "administrator, then re-probes every component."],
         ["7. Finish", "Nothing", "Summary. Close to open the sign-in window."]],
        [37 * mm, 54 * mm, 74 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "If a step fails, the wizard reports the actual error from the tool or "
        "database rather than a generic message. Fix the underlying cause and "
        "use Back and Next to retry \u2014 nothing partial is left behind.",
    )])
    add([PageBreak()])

    # =================================================================== 6
    add(h1("Installation layout"))
    add([p(
        "Application files and operator data are deliberately separated. The "
        "application directory is replaced on upgrade; the data directory is "
        "not."
    )])
    add([table(
        ["Location", "Contents"],
        [["C:\\Program Files\\AETHRA-SEC", "The executable, the bundled Python "
          "runtime, libraries and assets. Replaced on upgrade."],
         ["C:\\ProgramData\\AETHRA-SEC", "The data directory, created by the "
          "installer with modify permission for users."],
         ["  \\logs", "Application log and interface state."],
         ["  \\captures", "Packet capture files, bounded by the ring buffer."],
         ["  \\reports_output", "Generated reports."],
         ["  configuration file", "Database and SMTP settings. Tightened by "
          "the application when setup writes it, because it holds passwords."],
         ["MySQL / MariaDB", "All security records: hosts, alerts, incidents, "
          "findings, audit trail. Outside both directories above."]],
        [58 * mm, 107 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "important",
        "The configuration file contains the database password and, if "
        "configured, the SMTP password. Do not copy it into a report, an "
        "issue tracker or a version control system.",
    )])
    add([PageBreak()])

    # =================================================================== 7
    add(h1("Database setup"))
    add([p(
        "AETHRA-SEC stores every security record in MySQL or MariaDB. The "
        "setup wizard provisions this for you: it creates the schema if it "
        "does not exist and applies every migration in order. You do not need "
        "to create tables by hand."
    )])
    add([h2("Applying the schema manually")])
    add([p(
        "If you prefer to provision the schema yourself, the repository ships "
        "a generated SQL file. It contains the reference rows a working "
        "installation needs \u2014 roles, permissions, settings and the "
        "mitigation knowledge base \u2014 and no user accounts and no security "
        "records."
    )])
    add([mono(
        "mysql -u root -p < sql\\aethra_sec_schema.sql\n"
        "python scripts\\init_db.py"
    )])
    add([h2("Migrations")])
    add([p(
        "The schema is versioned by forward-only migrations recorded in the "
        "<font face='Courier' size='8'>schema_migrations</font> table. On "
        "startup AETHRA-SEC applies any migration newer than the recorded "
        "version. Start with <font face='Courier' size='8'>--no-migrate</font> "
        "to skip this, for example when running under a least-privilege "
        "account that cannot alter tables."
    )])
    add([Spacer(1, 2 * mm), callout(
        "important",
        "Never drop or recreate the database as part of a normal installation "
        "or upgrade. Migrations are additive and preserve your existing hosts, "
        "alerts, findings and audit trail.",
    )])
    add([h2("Least-privilege account")])
    add([p(
        "After the first run the application needs only SELECT, INSERT, UPDATE "
        "and DELETE. CREATE, ALTER, INDEX, REFERENCES and DROP are needed only "
        "while migrations run. The shipped SQL file documents a suitable grant."
    )])
    add([PageBreak()])

    # =================================================================== 8
    add(h1("Administrator account"))
    add([p(
        "The first administrator is created by the setup wizard. Further "
        "accounts are created inside the application from the Users screen "
        "(Section 23)."
    )])
    add([table(
        ["Field", "Meaning"],
        [["Username", "The sign-in name. Must be unique."],
         ["Password", "Shown in this manual only as "
                      "&lt;administrator password&gt;. Stored as an Argon2id "
                      "hash; the plain value is never written anywhere."],
         ["Full name", "Optional display name."],
         ["Email", "Optional. Used for notifications when SMTP is configured."],
         ["Role", "ADMIN or USER. Roles carry named permissions which every "
                  "service re-checks independently of the interface."],
         ["Status", "Active or inactive. The last active administrator cannot "
                    "be deactivated or demoted."]],
        [32 * mm, 133 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "Two-factor authentication is not part of the current implementation "
        "and is not described in this manual.",
    )])
    add([PageBreak()])

    # =================================================================== 9 (Nmap)
    add(h1("Nmap configuration"))
    add([p(
        "Nmap performs host discovery and vulnerability assessment. "
        "AETHRA-SEC locates the executable on PATH or at its standard install "
        "location, and the setup wizard reports the path and version it "
        "actually ran."
    )])
    add([h2("Authorisation boundary")])
    add([p(
        "AETHRA-SEC refuses to scan outside a configured set of networks. The "
        "boundary is enforced in the service layer, not in the interface, so "
        "it cannot be bypassed by the screen. It defaults to private ranges "
        "and loopback; scanning public addressing requires an explicit, "
        "deliberate change."
    )])
    add([mono(
        "AETHRA_AUTHORIZED_NETWORKS=192.168.0.0/16,10.0.0.0/8,"
        "172.16.0.0/12,127.0.0.0/8\n"
        "AETHRA_ALLOW_PUBLIC_TARGETS=false"
    )])
    add([callout(
        "important",
        "Only assess hosts you are authorised to assess. Widening the "
        "boundary does not confer authorisation.",
    )])
    add([PageBreak()])

    # =================================================================== 10
    add(h1("Network interface and capture visibility"))
    add([p(
        "This is the section most likely to explain an unexpected result, and "
        "it is about your network rather than about AETHRA-SEC."
    )])
    add([h2("Choosing an interface")])
    add([p(
        "AETHRA-SEC enumerates real adapters and presents the interface "
        "associated with the active default route first, ahead of virtual, "
        "disconnected and loopback adapters. It never silently selects an "
        "arbitrary adapter, and you can always choose manually. The selected "
        "adapter, its description and its address are shown on the Live "
        "Monitoring screen."
    )])
    add([h2("What a capture interface can and cannot see")])
    add([p(
        "AETHRA-SEC displays only what Npcap delivers to the selected "
        "interface. Two mechanisms are commonly confused:"
    )])
    add(bullets([
        "<b>Promiscuous mode</b> lets an adapter keep frames that reach it "
        "but are addressed to some other device.",
        "<b>Mirroring (SPAN) or a network TAP</b> is what causes another "
        "device's frames to reach the interface at all.",
    ]))
    add([p(
        "Promiscuous mode alone therefore cannot make a switched or wireless "
        "network deliver another device's unicast traffic. AETHRA-SEC always "
        "requests promiscuous mode; whether the adapter grants it is a "
        "property of the driver."
    )])
    add([Spacer(1, 2 * mm), callout(
        "important",
        "On Wi-Fi, a station is not delivered other stations' unicast frames, "
        "and under WPA2/WPA3 each station's traffic is encrypted with its own "
        "pairwise key. Many Windows Wi-Fi adapters also report promiscuous "
        "mode as unsupported outright. To monitor other devices you need an "
        "authorised observation point: switch SPAN or port mirroring, a "
        "network TAP, or a capture point on the gateway or router.",
    )])
    add([h2("Checking what you can actually see")])
    add([p(
        "The capture diagnostic reports, from real captured frames rather "
        "than from the host inventory, how many local and non-local hosts "
        "have been observed and how many peer unicast frames arrived. A host "
        "recorded in the Hosts table was seen at some point; that is not "
        "evidence that its traffic is visible now. Windows reports adapter "
        "capability directly:"
    )])
    add([mono("netsh wlan show wirelesscapabilities")])
    add([PageBreak()])

    # =================================================================== 11
    add(h1("Snort configuration"))
    add([p(
        "Snort is optional. AETHRA-SEC <b>reads alerts that a Snort sensor "
        "has already written</b>; it never launches or supervises Snort, and "
        "it does not ship or author Snort rules. Detection quality is a "
        "property of your rule set."
    )])
    add([h2("The alert path")])
    add([mono(
        "network traffic  ->  Snort  ->  rule match  ->  alert output\n"
        "                 ->  AETHRA-SEC ingest  ->  MySQL  ->  IDS Alerts"
    )])
    add([h2("Transports")])
    add([p(
        "Configure how AETHRA-SEC receives alerts with "
        "<font face='Courier' size='8'>AETHRA_SNORT_TRANSPORT</font>:"
    )])
    add([table(
        ["Value", "How alerts arrive"],
        [["file", "AETHRA-SEC tails a Snort alert file (alert_fast, alert_csv "
                  "or alert_json). Recommended on Windows."],
         ["unixsock", "Snort's alert_unixsock plugin, on Linux or WSL."],
         ["tcp", "AETHRA-SEC listens on a TCP port for line-oriented alerts."],
         ["syslog", "AETHRA-SEC listens on a UDP syslog port."],
         ["disabled", "No ingest. The interface reports Snort unavailable."]],
        [26 * mm, 139 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "With Snort disabled or absent, AETHRA-SEC's own traffic-analysis "
        "detection rules continue to raise anomalies. The interface "
        "distinguishes the two sources rather than presenting them as one.",
    )])
    add([PageBreak()])

    # =================================================================== 12
    add(h1("First launch"))
    add([p("A working first session, in order:")])
    add([table(
        ["#", "Action", "What to confirm"],
        [["1", "Start AETHRA-SEC from the shortcut",
          "Accept the elevation prompt. Capture needs it."],
         ["2", "Complete the setup wizard", "Seven steps, Section 5."],
         ["3", "Sign in", "With the administrator account you just created."],
         ["4", "Open System Health",
          "Database, Nmap, TShark, capture and Snort are probed live."],
         ["5", "Open Live Monitoring",
          "Confirm the adapter shown is the one you intend to monitor."],
         ["6", "Start capture", "Packets should begin arriving within seconds."],
         ["7", "Open the Dashboard",
          "Counters reflect what the subsystems actually reported."]],
        [10 * mm, 68 * mm, 87 * mm])])
    add([Spacer(1, 3 * mm), h2("Running the health check without the interface")])
    add([mono("aethra-sec-cli.exe --check")])
    add([PageBreak()])

    # =================================================================== 13
    add(h1("Signing in"))
    add([step_heading("Step 1 \u2014 open AETHRA-SEC and sign in")])
    add(shot("login", "The AETHRA-SEC sign-in window."))
    add(steps([
        "Start AETHRA-SEC from the desktop or Start menu shortcut and accept "
        "the elevation prompt. Live capture needs an elevated process.",
        "Enter your account username.",
        "Enter your password. Select <i>show</i> if you need to check what "
        "you typed.",
        "Select <b>Sign in</b>. The console opens on the screen you last used, "
        "if your role still permits it.",
    ]))
    add([Spacer(1, 3 * mm), table(
        ["Topic", "Behaviour"],
        [["Sign in", "Username and password. The console opens on the screen "
                     "you last used, if your role still permits it."],
         ["Failed attempts", "Every attempt is recorded, successful or not, "
                             "with the host it came from."],
         ["Lockout", "Repeated failures lock the account. An administrator "
                     "unlocks it from the Users screen."],
         ["Sessions", "Active sessions are listed on the Users screen and can "
                      "be ended by an administrator."],
         ["Sign out", "Returns to the sign-in window without restarting the "
                      "application or the background services."]],
        [32 * mm, 133 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "Password recovery requests raised at the sign-in screen appear in a "
        "queue on the Users screen. Nothing changes until an administrator "
        "decides.",
    )])
    add([PageBreak()])

    # =================================================================== 14
    add(h1("Dashboard"))
    add([p(
        "The landing screen: live security posture assembled from real "
        "subsystem data. Figures come from stored records and live counters, "
        "never from estimates."
    )])
    add([step_heading("Step 2 \u2014 read the security posture")])
    add(shot("dashboard", "The Dashboard, showing real counters."))
    add(steps([
        "Choose a reporting period. It changes the period counters only; the "
        "current-state band is unaffected.",
        "Read the current security state for active hosts, open ports and "
        "open findings as they stand now.",
        "Check the subsystem indicators in the header. Any one of them not "
        "green is explained on the System Health screen.",
    ]))
    add([Spacer(1, 2 * mm)])
    add([table(
        ["Band", "What it shows"],
        [["Reporting period", "Today, Day, Month, Year, All data or Custom. "
                              "Changes which records the period counters "
                              "cover."],
         ["Period activity", "Packets, detections and findings inside the "
                             "selected period."],
         ["Current security state", "Active hosts, open ports and open "
                                    "findings as they stand now, unaffected "
                                    "by the reporting period."],
         ["Automated assessment", "The discovery to queue to Nmap to findings "
                                  "pipeline, including how many hosts are "
                                  "vulnerable, safe, or awaiting assessment."],
         ["Live monitoring", "Traffic and detection as it arrives."]],
        [40 * mm, 125 * mm])])
    add([PageBreak()])

    # =================================================================== 15
    add(h1("Live Monitoring"))
    add([p("Live packet capture and traffic analysis, driven through TShark.")])
    add([step_heading("Step 3 \u2014 start capturing traffic")])
    add(shot("traffic", "Live Monitoring during a real capture."))
    add(steps([
        "Select <b>Live Monitoring</b> in the sidebar.",
        "Choose the capture interface. The routing interface is offered "
        "first; read Section 10 before choosing another.",
        "Leave the capture filter empty to capture everything, or enter a "
        "BPF expression to restrict what TShark captures at all.",
        "Select <b>Start capture</b>. Packets begin arriving within seconds "
        "and the status chip changes to CAPTURING.",
        "Use the view buttons \u2014 All Traffic, Incoming, Outgoing, Transit, "
        "HTTP, HTTPS/TLS, DNS, TCP, UDP, ICMP, ARP \u2014 to narrow what is "
        "displayed. This never restarts capture.",
        "Double-click any packet row to open its full detail.",
        "Select <b>Stop capture</b> when finished. The TShark process ends "
        "with it.",
    ]))
    add(detail("traffic", "Enlarged: the live packet table. Each row is a real captured frame, with its source, destination, protocol, ports, length and direction."))
    add([h2("The capture path")])
    add([mono(
        "network  ->  Npcap  ->  TShark  ->  bounded queue\n"
        "         ->  capture worker  ->  batched UI update / batched writes"
    )])
    add([h2("Capture filter versus display filter")])
    add([p(
        "These are separate and behave differently. A <b>capture filter</b> is "
        "applied by TShark and controls what is captured at all; traffic it "
        "excludes is gone. A <b>display filter</b> only changes which already "
        "captured packets are shown. Changing a display filter never restarts "
        "capture and never starts a second capture process."
    )])
    add([h2("Views")])
    add([p(
        "All, Incoming, Outgoing, Transit, HTTP, HTTPS/TLS, TCP, UDP, ICMP, "
        "DNS and ARP. <b>Transit</b> means neither endpoint is this machine "
        "\u2014 traffic between two other devices, shown only when it was "
        "genuinely captured."
    )])
    add([Spacer(1, 2 * mm), callout(
        "important",
        "For HTTPS, AETHRA-SEC shows only metadata the capture actually "
        "carries: addresses, ports, TLS version, the server name from a "
        "ClientHello when present, and a domain correlated from observed DNS. "
        "It does not decrypt traffic and does not extract credentials. Where "
        "no domain is available the row reads Unknown/Encrypted rather than "
        "showing a guess.",
    )])
    add([PageBreak()])

    # =================================================================== 16
    add(h1("IDS Alerts"))
    add([p(
        "Alerts received from Snort over the configured transport, alongside "
        "anomalies raised by AETHRA-SEC's own traffic rules. The two sources "
        "are distinguished rather than merged."
    )])
    add([step_heading("Step 4 \u2014 review an alert")])
    add(shot("alerts", "IDS Alerts."))
    add(steps([
        "Select <b>Alerts</b> in the sidebar.",
        "Select an alert row. Rows not yet reviewed carry the UNREVIEWED "
        "marker.",
        "Select <b>Details</b>, or double-click the row, to open the full "
        "alert with its mitigation recommendation.",
        "Record your judgement with <b>True positive</b> or "
        "<b>False positive</b>.",
        "Select <b>Mark reviewed</b>. The UNREVIEWED marker clears and the "
        "sidebar counter follows, because both read the same stored state.",
    ]))
    add(detail("alerts", "Enlarged: the alert table, showing severity, signature, source, destination and review state."))
    add([h2("Reviewing an alert")])
    add([table(
        ["Control", "Effect"],
        [["Details", "Opens the full alert, including the mitigation "
                     "recommendation matched from the knowledge base."],
         ["Mark reviewed", "Records that the alert has been reviewed. The "
                           "UNREVIEWED marker and the sidebar counter read "
                           "the same stored state."],
         ["True positive", "Records the analyst's evaluation."],
         ["False positive", "Records the analyst's evaluation."],
         ["Export", "Exports the currently filtered set, not only the "
                    "selected row."]],
        [34 * mm, 131 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "Acknowledge, Escalate and Benign/expected were removed as unused "
        "actions and are not available. Records already in those states keep "
        "them and the Status and Evaluation columns still report them "
        "truthfully; nothing new can be put into them.",
    )])
    add([PageBreak()])

    # =================================================================== 17
    add(h1("Notifications"))
    add([p(
        "A notification is created when a real event is recorded \u2014 a new "
        "alert at or above the configured severity, a finished or failed "
        "assessment, or a subsystem failure. The badge count and the alert "
        "sound are driven by the same stored record."
    )])
    add([table(
        ["Setting", "Effect"],
        [["notifications.enabled", "Master switch for creating notifications."],
         ["notifications.min_severity", "The lowest alert severity that "
                                        "raises a notification."],
         ["notifications.sound_enabled", "Whether a sound plays."],
         ["notifications.sound_min_level", "The lowest notification level "
                                           "that sounds."],
         ["notifications.sound_dedup_seconds", "Repeats of the same finding "
                                               "inside this window fold into "
                                               "the first sound. The record "
                                               "still counts every "
                                               "occurrence."]],
        [62 * mm, 103 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "note",
        "The packaged alert sound is verified at startup. If it is missing or "
        "cannot be played, the Settings screen states so and the system sound "
        "is used instead \u2014 the failure is reported rather than passing as "
        "silence.",
    )])
    add([PageBreak()])

    # =================================================================== 18
    add(h1("Vulnerability Assessment"))
    add([p("Authorised Nmap assessment: discovery, port state, service and OS "
           "detection.")])
    add([step_heading("Step 5 \u2014 assess a host")])
    add(shot("vulnerabilities", "Vulnerability Assessment."))
    add(steps([
        "Select <b>Vulnerabilities</b> in the sidebar.",
        "Confirm the target is inside the authorised networks. Assessment is "
        "refused outside them, in the service layer.",
        "Automatic assessment queues discovered hosts on its own. To assess "
        "one now, select it and start a scan.",
        "Watch the assessment state move through QUEUED and SCANNING to "
        "COMPLETED, or to NO RESPONSE if the host never answered.",
        "Read the security result: Vulnerable, Safe, or a dash. A dash means "
        "no conclusion is available \u2014 not that the host is safe.",
    ]))
    add([h2("Three states that are easy to confuse")])
    add([table(
        ["Dimension", "Values", "Meaning"],
        [["Host reachability", "UP / OFFLINE / UNKNOWN",
          "Whether the host answered."],
         ["Assessment state", "NOT ASSESSED / QUEUED / SCANNING / COMPLETED / "
          "NO RESPONSE / FAILED", "How far assessment has got."],
         ["Security result", "Vulnerable / Safe / \u2014",
          "What the assessment concluded. A dash means no conclusion is "
          "available, not that the host is safe."]],
        [34 * mm, 58 * mm, 73 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "important",
        "An open port is exposure, not a vulnerability. A host is reported "
        "Vulnerable only on confirmed finding evidence. A rescan supersedes a "
        "host's earlier findings by resolving them rather than deleting them, "
        "so assessment history is preserved.",
    )])
    add([PageBreak()])

    # =================================================================== 19
    add(h1("Hosts"))
    add([p(
        "The network as the console currently understands it: hosts observed "
        "in captured traffic or discovered by assessment."
    )])
    add([step_heading("Step 6 \u2014 host inventory")])
    add(shot("hosts", "Host Inventory."))
    add(steps(['Select <b>Hosts</b> in the sidebar.', 'Read the hostname together with its provenance: a name learned from an mDNS announcement is not the same evidence as reverse DNS.', 'Check last-seen to judge whether an entry is current.']))
    add([table(
        ["Column", "Source"],
        [["IP address", "Observed in captured traffic or reported by a scan."],
         ["MAC address", "Recorded only when the frame genuinely carries the "
                         "host's own hardware address."],
         ["Hostname", "Reverse DNS, NetBIOS, or a device's own mDNS "
                      "announcement. The provenance is recorded alongside it."],
         ["Operating system", "Nmap OS detection, with its confidence."],
         ["First / last seen", "From real observations."],
         ["Assessment status", "See Section 18."],
         ["Security result", "See Section 18."]],
        [40 * mm, 125 * mm])])
    add([PageBreak()])

    # =================================================================== 20
    add(h1("Mitigation"))
    add([p(
        "A recommendation-only knowledge base. AETHRA-SEC never applies a "
        "mitigation; every recommendation requires a human decision."
    )])
    add([step_heading("Step 7 \u2014 mitigation guidance")])
    add(shot("mitigation", "Mitigation Guidance."))
    add(steps(['Select <b>Mitigation</b> in the sidebar.', 'Find the recommendation matched to a threat category or service.', 'Apply it yourself. AETHRA-SEC never applies a mitigation.']))
    add([p(
        "Recommendations shown against an alert are matched from this base by "
        "service, severity, threat category or an explicit mapping. When no "
        "entry matches, the alert detail says so rather than offering generic "
        "advice, and a failed lookup reports the failure."
    )])
    add([PageBreak()])

    # =================================================================== 21
    add(h1("Reports"))
    add([p(
        "Reports are generated from stored records only, so every figure is "
        "traceable to the rows behind it."
    )])
    add([step_heading("Step 8 \u2014 reports")])
    add(shot("reports", "Reports."))
    add(steps(['Select <b>Reports</b> in the sidebar.', 'Choose a report type, a scope and a period.', 'Generate. The file is written to the reports directory shown on the screen, and the run is recorded so it can be reproduced.']))
    add([p(
        "Choose a report type, a scope and a period, then generate. Output is "
        "written to the reports directory shown in Section 6, and the "
        "generated file, its scope and its record counts are recorded so a "
        "report can be reproduced."
    )])
    add([PageBreak()])

    # =================================================================== 22
    add(h1("Logs and Audit"))
    add([p(
        "An append-only audit trail with SHA-256 chained integrity hashes: "
        "altering a historical entry breaks verification and the application "
        "reports it."
    )])
    add([step_heading("Step 9 \u2014 logs & audit")])
    add(shot("logs", "Logs & Audit."))
    add(steps(['Select <b>Logs &amp; Audit</b> in the sidebar.', 'Filter by period, actor or action.', 'Export the filtered set if you need it outside the application.']))
    add([p(
        "Security-relevant actions are recorded with the actor, the target and "
        "the outcome. Sign-in activity, administrative changes and system "
        "errors are filterable and exportable. Credentials are never written "
        "to the audit trail."
    )])
    add([PageBreak()])

    # =================================================================== 23
    add(h1("User administration"))
    add([p(
        "Account registration, password recovery, roles, sign-in history and "
        "active sessions. Administrator only."
    )])
    add([step_heading("Step 10 \u2014 user management")])
    add(shot("users", "User Management."))
    add(steps(['Select <b>Users</b> in the sidebar.', 'Select an account, then <b>Edit</b> to change its identity or role. Doing so sets Date Modified.', 'Use <b>Unlock</b> to clear a lockout, or <b>Force sign-out</b> to end an active session.', '<b>Create account</b> adds a new operator. A new account shows a dash under Date Modified until it is first edited.']))
    add(detail("users", "Enlarged: the accounts table. The first column is the database record identifier; Date Modified is blank for an account never edited."))
    add([table(
        ["Column", "Meaning"],
        [["ID", "The database record identifier \u2014 the real primary key, "
                "not a row number."],
         ["Username", "Sign-in name, unique."],
         ["Full name / Email", "Display name and contact address."],
         ["Role", "ADMIN or USER."],
         ["Status", "Active or inactive."],
         ["Failed logins", "Consecutive failures; drives lockout."],
         ["Last sign-in", "Last authentication activity."],
         ["Last host", "Where that sign-in came from."],
         ["Created", "Account creation timestamp."],
         ["Date Modified", "The last time an administrator changed the "
                           "account's identity or configuration. It does not "
                           "move on sign-in, on a failed login, or on an "
                           "automatic lockout. A dash means the account has "
                           "not been edited since it was created."]],
        [32 * mm, 133 * mm])])
    add([Spacer(1, 2 * mm), p(
        "Available actions: Create account, Edit, Reset password, Unlock, "
        "Deactivate, Activate, Force sign-out and Refresh. The last active "
        "administrator cannot be deactivated or demoted."
    )])
    add([PageBreak()])

    # =================================================================== 24
    add(h1("System Health"))
    add([p(
        "Live subsystem probes, re-run every time the screen is opened. A "
        "component is reported on what was actually observed, never assumed."
    )])
    add([step_heading("Step 11 \u2014 system health")])
    add(shot("health", "System Health."))
    add(steps(['Select <b>System Health</b> in the sidebar.', 'Every component is re-probed as the screen opens.', 'Read the detail beside any component that is not healthy: it carries the actual error, not a generic message.']))
    add([table(
        ["Component", "What is probed"],
        [["application", "Version, uptime and runtime statistics."],
         ["database", "Connectivity, schema version and migration state."],
         ["nmap", "Executable, its path and the version that ran."],
         ["tshark", "Executable and version; capture availability."],
         ["capture", "Interface state, counters and drops reported by the "
                     "capture engine."],
         ["snort", "Ingest transport state and last alert received."]],
        [34 * mm, 131 * mm])])
    add([PageBreak()])

    # =================================================================== 25
    add(h1("Settings"))
    add([p(
        "Seventy-two runtime settings are stored in the database and take "
        "effect without restarting, grouped by area. Each carries its purpose, "
        "its permitted range and its default in the interface."
    )])
    add([step_heading("Step 12 \u2014 system settings")])
    add(shot("settings", "System Settings."))
    add(steps(['Select <b>Settings</b> in the sidebar.', 'Choose the group you need.', 'Change a value. It is stored in the database and takes effect without restarting.']))
    add([table(
        ["Group", "Count", "Covers"],
        [["detection", "13", "Anomaly thresholds and detection windows"],
         ["assessment", "11", "Automatic assessment scope, cadence, timeouts"],
         ["capture", "11", "Queue size, pcap ring bounds, batching, row-rate "
                           "cap, domain correlation"],
         ["notifications", "8", "Enablement, minimum severity, sound"],
         ["security", "8", "Lockout, session and password policy"],
         ["retention", "6", "How long each class of record is kept"],
         ["correlation", "5", "Incident grouping"],
         ["backup", "4", "Scheduled backup behaviour"],
         ["hosts", "3", "Inventory ageing and offline marking"],
         ["ui", "3", "Refresh cadence and table bounds"]],
        [32 * mm, 16 * mm, 117 * mm])])
    add([PageBreak()])

    # =================================================================== 26
    add(h1("Help and About"))
    add([step_heading("Step 13 \u2014 about aethra-sec")])
    add(shot("about", "About AETHRA-SEC."))
    add(steps(['Select <b>About</b> in the sidebar to confirm the version and the conditions of use.']))
    add([p(
        "The About screen reports the system identity, version, technology "
        "stack and the conditions of use the application operates under. The "
        "Help screen covers in-application guidance and keyboard shortcuts, "
        "including the command palette."
    )])
    add([PageBreak()])

    # =================================================================== 27
    add(h1("Updating AETHRA-SEC"))
    add([callout(
        "note",
        "An automated update procedure is not currently provided by the "
        "application. AETHRA-SEC does not check for updates and cannot "
        "update itself.",
    )])
    add([p("To upgrade, install the newer build over the existing one:")])
    add([table(
        ["Step", "Detail"],
        [["1. Back up", "Take a database backup. The security records live "
                        "there, not in the install directory."],
         ["2. Close", "Stop capture and close AETHRA-SEC so no file is in use."],
         ["3. Install", "Run the newer AETHRA-SEC-Setup.exe. It detects the "
                        "existing installation and upgrades in place."],
         ["4. Migrate", "On the next start, migrations newer than the recorded "
                        "schema version are applied automatically."],
         ["5. Verify", "Open System Health and confirm the schema version and "
                       "every component."]],
        [26 * mm, 139 * mm])])
    add([Spacer(1, 3 * mm), callout(
        "important",
        "Do not drop or recreate the database as part of an upgrade. "
        "Migrations are additive and preserve hosts, alerts, findings and the "
        "audit trail. Your configuration file is in the data directory and is "
        "not replaced by the installer.",
    )])
    add([PageBreak()])

    # =================================================================== 28
    add(h1("Uninstalling AETHRA-SEC"))
    add([p(
        "Use <i>Uninstall AETHRA-SEC</i> from the Start menu, or Apps and "
        "Features. The uninstaller is explicit about what it removes."
    )])
    add([table(
        ["What", "What happens"],
        [["Application files", "Removed from the install directory."],
         ["Data directory", "<b>You are asked.</b> It holds the configuration "
                            "file, logs, reports and capture files. The "
                            "default answer is to keep it, and a second "
                            "confirmation is required to delete it."],
         ["Database", "<b>Never removed.</b> Hosts, alerts, incidents, "
                      "findings and the audit trail stay in MySQL, because an "
                      "uninstaller must not destroy security evidence."]],
        [38 * mm, 127 * mm])])
    add([Spacer(1, 3 * mm), h2("Removing the database deliberately")])
    add([p(
        "If you genuinely want the security history gone, drop the schema "
        "named in the configuration file using your database administration "
        "tool. This cannot be undone."
    )])
    add([PageBreak()])

    # =================================================================== 29
    add(h1("Troubleshooting"))
    add([table(
        ["Symptom", "Likely cause and what to check", "Resolution"],
        [["Application will not start",
          "Configuration missing or unreadable; database unreachable at "
          "startup.",
          "Run the diagnostics shortcut (--check). Re-run setup with --setup."],
         ["Database unavailable",
          "Server not running, wrong host or port, credentials changed.",
          "Start MySQL/MariaDB. Confirm the settings in the configuration "
          "file. System Health reports the actual driver error."],
         ["Nmap unavailable",
          "Not installed, or not on PATH.",
          "Install Nmap or set its path. Verify with nmap --version."],
         ["Npcap unavailable",
          "Not installed, or the console is not elevated.",
          "Install Npcap (included with Wireshark). Start from the shortcut, "
          "which prompts for elevation."],
         ["TShark unavailable",
          "Wireshark not installed, or TShark not on PATH.",
          "Install Wireshark. Verify with tshark --version."],
         ["Snort unavailable",
          "Transport disabled, or no sensor is writing alerts.",
          "Set AETHRA_SNORT_TRANSPORT and confirm the sensor is running. "
          "AETHRA-SEC never starts Snort."],
         ["No packets captured",
          "Wrong adapter selected; a capture filter is excluding everything.",
          "Confirm the adapter on Live Monitoring is the routing interface. "
          "Clear the capture filter."],
         ["Other devices not visible",
          "The network is not delivering their traffic to this interface.",
          "Section 10. This needs SPAN, a TAP or a gateway capture point, not "
          "a software change."],
         ["IDS alerts missing",
          "Snort not writing, transport mismatch, or severity below the "
          "notification threshold.",
          "Check System Health, then the alert file path."],
         ["Notification sound missing",
          "Sound disabled, level below the threshold, or repeats folded by "
          "the dedup window.",
          "Check the notification settings in Section 17. Settings reports "
          "whether the packaged sound is usable."],
         ["Assessment fails",
          "Target outside the authorised boundary, or Nmap unavailable.",
          "Confirm the target is inside AETHRA_AUTHORIZED_NETWORKS. The "
          "failure records the actual Nmap error."],
         ["Application feels slow",
          "Very high packet rate, or a large reporting period.",
          "Counters show captured, displayed and dropped separately so the "
          "stage under pressure is visible."],
         ["Locked out",
          "Consecutive failed sign-ins.",
          "Another administrator unlocks the account from Users."],
         ["Report generation fails",
          "Reports directory not writable, or no records in the period.",
          "Check permissions on the reports directory; widen the period."],
         ["Installer fails",
          "Not elevated, or files in use.",
          "Run as administrator with AETHRA-SEC closed."]],
        [33 * mm, 68 * mm, 64 * mm])])
    add([PageBreak()])

    # =================================================================== 30
    add(h1("Security considerations and limitations"))
    add([h2("Handling of credentials and secrets")])
    add(bullets([
        "Account passwords are stored as Argon2id hashes and never in "
        "readable form.",
        "The configuration file holds the database and SMTP passwords. The "
        "application tightens its permissions when setup writes it.",
        "Credentials are never written to the audit trail, the logs or a "
        "report.",
        "Packet detail masks values the dissector identifies as credentials "
        "before they reach the interface. The bytes remain in the capture "
        "file; only the display is masked.",
    ]))
    add([h2("What AETHRA-SEC cannot do")])
    add(bullets([
        "It cannot decrypt HTTPS, and does not attempt to.",
        "It cannot recover Wi-Fi passwords or any other credential.",
        "It cannot see traffic the network does not deliver to its capture "
        "interface, whatever its settings say.",
        "It cannot start, stop or configure a Snort sensor.",
        "It does not update itself.",
    ]))
    add([h2("Data retention")])
    add([p(
        "Retention settings control how long each class of record is kept. "
        "Capture files are bounded by a ring buffer, so a long session cannot "
        "fill the disk; a packet whose capture file has been recycled can no "
        "longer be inspected in detail, and the inspector says so rather than "
        "showing something else."
    )])
    add([Spacer(1, 3 * mm), callout(
        "important",
        "AETHRA-SEC must only be operated against networks, hosts and "
        "interfaces you are explicitly authorised to monitor or assess. It "
        "performs no exploitation, no credential attacks and no automated "
        "mitigation. All mitigation output is advisory and requires a human "
        "decision.",
    )])

    return story
