"""Step-by-step mitigation procedures for the threat categories AETHRA-SEC detects.

Every Windows instruction here was verified against the Windows Defender
Firewall on a real Windows 11 host before it was written down:

* ``New-NetFirewallRule``, ``Get-NetFirewallRule``, ``Disable-NetFirewallRule``
  and ``Remove-NetFirewallRule`` exist in the ``NetSecurity`` module.
* ``-DisplayName``, ``-Direction``, ``-Action``, ``-Protocol``, ``-LocalPort``,
  ``-RemoteAddress``, ``-IcmpType``, ``-Profile``, ``-Enabled`` and
  ``-Description`` are real parameters of ``New-NetFirewallRule``.
* ``-Direction`` accepts Inbound and Outbound; ``-Action`` accepts Allow,
  Block and NotConfigured; ``-Enabled`` accepts True and False.
* The TCP, UDP and ICMPv4 rule shapes below were dry-run with ``-WhatIf``
  and accepted. Nothing was created.
* ``WF.msc`` exists at ``%SystemRoot%\\System32\\WF.msc``.
* ``Get-NetNeighbor`` exists in ``NetTCPIP`` and reports
  ``LinkLayerAddress``, which is how the host-sweep guide identifies a
  device by its hardware address rather than by a DHCP lease.
* ``-Protocol ICMPv4 -IcmpType 8 -RemoteAddress <addr>`` was dry-run and
  accepted, so an ICMP sweep can be blocked at the endpoint.
* ``-Protocol ARP`` is REJECTED - "The protocol is invalid." Windows
  Defender Firewall cannot filter ARP, because ARP is resolved below the
  layer it filters. The host-sweep guide says so outright instead of
  offering a rule that cannot exist, and this matters in practice: ARP
  sweeps are the commonest detection in the recorded data.
* ``Get-Service``, ``Stop-Service``, ``Start-Service``, ``Set-Service``
  and ``Get-Process`` exist in ``Microsoft.PowerShell.Management``, and
  ``Set-Service`` accepts ``-Name``, ``-StartupType`` and ``-Status``.
* ``Get-NetTCPConnection`` exposes ``LocalAddress``, ``LocalPort`` and
  ``OwningProcess``, so a listening port can be traced to the process
  that owns it before anything is stopped.
* ``Get-WindowsCapability`` and ``Remove-WindowsCapability`` exist in
  ``Dism``.
* ``sshd`` is NOT installed on this host. The SSH guide is therefore
  written conditionally: it says to establish what the target actually
  is first, because AETHRA-SEC running on Windows is no evidence that
  the host it scanned is Windows.

What was checked and is NOT claimed anywhere below: Windows Defender Firewall
has no rate limiting, no connection throttling and no SYN-flood or
denial-of-service protection. Searching the ``NetSecurity`` module for a
rate, throttle or flood control returns nothing; the only near-match is
``-ThrottleLimit``, which is PowerShell's generic limit on concurrent CIM
operations and has no effect on traffic. Where volumetric traffic has to be
absorbed, the guides say so and send the reader upstream rather than inventing
a capability the product does not have.

Placeholders are deliberate. ``<SOURCE_IP>``, ``<TARGET_IP>`` and ``<PORT>``
are filled from the alert being viewed when it carries them, and left visible
when it does not, so a command is never shown pre-filled with an address from
some other event.

Nothing here executes. These are strings stored in the database and shown to
an operator who decides what to do.
"""

from __future__ import annotations

#: Opening Windows Defender Firewall, used by every host-level procedure.
_OPEN_WF = (
    "Press Windows+R, type  wf.msc  and press Enter. Approve the "
    "Administrator prompt. This is Windows Defender Firewall with Advanced "
    "Security; it is the only firewall console that can create a scoped rule."
)

#: Appended to every procedure that creates a rule.
#: Deliberately carries no placeholder. It used to give an example name built
#: from <SOURCE_IP> and a <DATE>, which left a stray placeholder on every
#: exposure finding - those have no attacking source - and a <DATE> that
#: nothing ever fills. The operator is told what the name must identify.
_NAME_IT = (
    "Give the rule a name that identifies who made it, what it affects and "
    "when: the tool name, the port or address it covers, and the date you "
    "made the change. A rule nobody can identify later is a rule nobody "
    "dares remove."
)

HOST = "Windows Defender Firewall on the affected endpoint"
EDGE = "Authorised network gateway or perimeter firewall"
WEB = "Web server, reverse proxy, or web application firewall"


def _steps(*lines: str) -> str:
    """One step per line, numbered as stored."""
    return "\n".join(f"{i}. {line}" for i, line in enumerate(lines, start=1))


# ---------------------------------------------------------------------------
# The guides, keyed on the recommendation code already in the database.
# ---------------------------------------------------------------------------
GUIDES: dict[str, dict[str, str]] = {

    # -- Port scanning ------------------------------------------------------
    "MIT-PORT-SCAN": {
        "enforcement_point": (
            f"{HOST}, for restricting what the scanned host exposes.\n\n"
            "A host firewall cannot stop the scanning packets arriving - they "
            "have already reached the machine by the time Windows sees them. "
            "What it can do is make sure they find nothing worth having. "
            "Blocking the scanner's address is secondary and often pointless, "
            "because a scan is cheap to repeat from another address."
        ),
        "procedure_steps": _steps(
            "Before changing anything, establish whether the scan was "
            "authorised. An asset inventory agent, a scheduled vulnerability "
            "scan and an IT technician all produce this exact pattern. Check "
            "the source <SOURCE_IP> against your own inventory first.",
            "Open AETHRA-SEC's Vulnerability Assessment screen and look up "
            "<TARGET_IP>. The Ports & services tab lists what is actually "
            "open. That list, not the scan, is your exposure.",
            "For each open port, decide whether the service needs to be "
            "reachable from where the scan came from. A port that no one "
            "outside the host needs is the finding; the scan merely revealed "
            "it.",
            "If a service is not needed, stop and disable it rather than "
            "firewalling it. A disabled service cannot be exploited through a "
            "firewall misconfiguration.",
            f"For a service that must stay but should not be reachable from "
            f"everywhere: {_OPEN_WF}",
            "Select Inbound Rules, then New Rule in the Actions pane on the "
            "right.",
            "Choose Port, then Next. Choose TCP or UDP and enter the specific "
            "port in Specific local ports. Do not use All local ports.",
            "Choose Allow the connection if secure is not required - choose "
            "Allow the connection - then Next.",
            "On the Profile page, tick only the profiles that apply to the "
            "network this host is on. Domain, Private and Public are separate; "
            "a rule on the wrong profile does nothing.",
            "Name the rule and finish. Then reopen it, go to the Scope tab, "
            "and under Remote IP address choose These IP addresses and add "
            "only the subnets that legitimately need the service. This is the "
            "step that actually restricts exposure.",
            "Equivalent PowerShell, run in an Administrator PowerShell window. "
            "Replace <PORT> and the address list, and keep the name: "
            "New-NetFirewallRule -DisplayName 'AETHRA-SEC restrict <PORT>' "
            "-Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT> "
            "-RemoteAddress 192.168.1.0/24 -Profile Domain,Private",
            "Only if you have verified evidence that <SOURCE_IP> is hostile "
            "and is not a shared address, add a block rule for it: "
            "New-NetFirewallRule -DisplayName 'AETHRA-SEC block <SOURCE_IP>' "
            "-Direction Inbound -Action Block -RemoteAddress <SOURCE_IP>. "
            "Check first that the address is not a NAT gateway or proxy that "
            "legitimate users also sit behind.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "Confirm the rule exists and is enabled: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' | "
            "Select-Object DisplayName, Enabled, Direction, Action",
            "Confirm the scope took effect: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' | "
            "Get-NetFirewallAddressFilter",
            "From an address that SHOULD still reach the service, connect to "
            "it and confirm it still works. Test-NetConnection <TARGET_IP> "
            "-Port <PORT> reports TcpTestSucceeded True when the path is open.",
            "From an address that should NOT reach it, repeat the same test "
            "and confirm it now fails. Only do this from a host you are "
            "authorised to test from.",
            "Re-run the vulnerability assessment against <TARGET_IP> and "
            "confirm the port list is what you intended.",
            "Watch the IDS Alerts screen. A repeat scan from the same source "
            "will still be DETECTED - the packets still arrive - but it should "
            "now find fewer open ports.",
        ),
        "rollback_steps": _steps(
            "Find the exact rule you added: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*'",
            "Disable it first rather than deleting it, so you can put it back "
            "in one command if the problem was something else: "
            "Disable-NetFirewallRule -DisplayName 'AETHRA-SEC block <SOURCE_IP>'",
            "Confirm the service is reachable again from the affected client.",
            "Delete it only once you are satisfied it was the cause: "
            "Remove-NetFirewallRule -DisplayName 'AETHRA-SEC block <SOURCE_IP>'",
            "Never disable the firewall as a whole to test this. Disable the "
            "one rule you added, by its name.",
        ),
        "operational_warnings": (
            "A scan is not a breach. Detecting one means somebody looked; it "
            "does not mean anything was taken.\n\n"
            "An open port is not automatically a vulnerability - a web server "
            "is supposed to have 443 open.\n\n"
            "Blocking the source address can disconnect legitimate users if "
            "that address is a NAT gateway, proxy or shared laboratory "
            "machine. Check what sits behind it first.\n\n"
            "A host firewall rule does not stop the scan traffic reaching the "
            "machine. If the scanning volume itself is the problem, that is a "
            "network-edge matter."
        ),
    },

    # -- Host sweep ---------------------------------------------------------
    # The commonest detection on a real campus LAN, and the one most often
    # benign. The procedure therefore starts with identification and spends
    # most of its length there, because blocking first is usually the wrong
    # move and sometimes impossible.
    "MIT-HOST-SWEEP": {
        "enforcement_point": (
            "Depends entirely on the protocol in the alert, and for the "
            "commonest case there is no host-level option at all.\n\n"
            "If the Protocol field says ARP, Windows Defender Firewall cannot "
            "help: ARP is resolved below the layer the firewall filters, and "
            "New-NetFirewallRule rejects -Protocol ARP outright with \"The "
            "protocol is invalid\". This was tested on a real Windows 11 "
            "host. An ARP sweep on your own subnet cannot be blocked from the "
            "endpoint by any firewall rule, and no rule below pretends "
            "otherwise.\n\n"
            f"If the Protocol field says ICMP, {HOST} can block echo "
            "requests from the source.\n\n"
            f"{EDGE} or the access switch is the only place an ARP sweep can "
            "be constrained, and only if that equipment supports it. Whether "
            "it does is a question for whoever administers it."
        ),
        "procedure_steps": _steps(
            "Read the alert before acting. The observation line states how "
            "many distinct hosts <SOURCE_IP> contacted, over what interval, "
            "and what share of them were inside one range. A sweep is a "
            "range being walked; that is all the detection claims.",
            "Identify the device, not the address. Addresses move with DHCP; "
            "the hardware address does not. On the same subnet, read it from "
            "the neighbour cache: Get-NetNeighbor -AddressFamily IPv4 | "
            "Select-Object IPAddress, LinkLayerAddress, State",
            "Look the first three octets of that hardware address up as an "
            "OUI to get the manufacturer, and cross-check <SOURCE_IP> against "
            "the Vulnerability Assessment screen's host inventory, which "
            "records the vendor and hostname it discovered. A phone, a "
            "printer, a smart television or a router sweeping its own subnet "
            "is ordinary behaviour, not an attack.",
            "Rule out your own tooling before anything else. A network "
            "scanner, an asset inventory agent, a monitoring probe and "
            "AETHRA-SEC's own discovery scan all produce exactly this "
            "pattern. If the source is your own scanner, the correct outcome "
            "is to mark the alert reviewed and leave the network alone.",
            "Decide what the device actually is. Only if it is unidentified, "
            "or identified and does not belong on this network, is there "
            "anything to mitigate. Reconnaissance from a device you own and "
            "recognise is not an incident.",
            "If the Protocol field says ARP, stop here for firewall purposes. "
            "There is no host rule to add. Take it to whoever runs the "
            "switch, give them the hardware address, the time window and the "
            "subnet from this alert, and ask whether the switch supports port "
            "security or dynamic ARP inspection and whether it can be applied "
            "to that port. Do not follow configuration instructions for "
            "equipment you have not confirmed.",
            f"If the Protocol field says ICMP and the device is confirmed "
            f"unwanted: {_OPEN_WF}",
            "Select Inbound Rules, then New Rule, then Custom, then All "
            "programs, then Next. Set Protocol type to ICMPv4, click "
            "Customize, choose Specific ICMP types and tick Echo Request. "
            "Blocking every ICMP type breaks path discovery and diagnostics "
            "for everyone, so tick only that one.",
            "On the Scope page set Which remote IP addresses does this rule "
            "apply to? to These IP addresses and add only <SOURCE_IP>. A rule "
            "left at Any address blocks ping from your own administrators.",
            "Equivalent PowerShell, in an Administrator window: "
            "New-NetFirewallRule -DisplayName 'AETHRA-SEC block sweep "
            "<SOURCE_IP>' -Direction Inbound -Action Block -Protocol ICMPv4 "
            "-IcmpType 8 -RemoteAddress <SOURCE_IP> -Profile Domain,Private",
            "Record what you decided and why, against this alert, using the "
            "Evaluation field. The next person to see 1,000 sweeps from the "
            "same phone needs to know somebody already identified it.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "If you added no rule because the sweep was ARP, there is nothing "
            "to verify at the host. Confirm instead that you recorded the "
            "hardware address and passed it to the switch owner.",
            "If you added an ICMP rule, confirm it exists and is enabled: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' | "
            "Select-Object DisplayName, Enabled, Direction, Action",
            "Confirm the scope is the single source and not everything: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC block sweep "
            "<SOURCE_IP>' | Get-NetFirewallAddressFilter",
            "Confirm your own administrators can still reach the host: from "
            "a machine you are authorised to test from, Test-NetConnection "
            "<TARGET_IP> should still succeed.",
            "Expect the alerts to continue. Blocking echo requests stops the "
            "replies, not the probes, and an ARP sweep is not blocked at all. "
            "AETHRA-SEC reports what arrives on the wire, so a continuing "
            "sweep count is the detector working, not the mitigation failing.",
            "Watch the IDS Alerts screen over the following day and compare "
            "the host count in the observation line with what it was before. "
            "That number, not the alert count, tells you whether the "
            "behaviour changed.",
        ),
        "rollback_steps": _steps(
            "Find the exact rule: Get-NetFirewallRule -DisplayName "
            "'AETHRA-SEC block sweep <SOURCE_IP>'",
            "Disable it first, so it can be put back in one command: "
            "Disable-NetFirewallRule -DisplayName 'AETHRA-SEC block sweep "
            "<SOURCE_IP>'",
            "Confirm whatever stopped working is working again.",
            "Delete it once you are satisfied: Remove-NetFirewallRule "
            "-DisplayName 'AETHRA-SEC block sweep <SOURCE_IP>'",
            "Never disable the firewall as a whole to test this. Disable the "
            "one rule you added, by its name.",
            "If the switch owner changed a port setting on your behalf, ask "
            "them to reverse it separately. You cannot undo their change from "
            "this host.",
        ),
        "operational_warnings": (
            "A sweep is reconnaissance. It means something enumerated the "
            "subnet; it does not mean anything was accessed, and it is not a "
            "breach.\n\n"
            "Most sweeps on a campus or home LAN are legitimate. Phones "
            "looking for a casting target, printers announcing themselves, "
            "network scanners, DHCP servers and the router itself all walk "
            "the local range as designed. Treat an unexplained sweep as a "
            "question to answer, not a verdict.\n\n"
            "Windows Defender Firewall cannot filter ARP. If the alert says "
            "ARP, any instruction to block it at the endpoint is wrong, "
            "wherever it came from.\n\n"
            "Blocking echo requests from a source can break monitoring, "
            "diagnostics and clustering that legitimately rely on ping. "
            "Check what else uses that address first.\n\n"
            "The source address may be a NAT gateway, a router or a shared "
            "laboratory machine, in which case a block affects every device "
            "behind it.\n\n"
            "AETHRA-SEC only sees traffic that reaches its own capture "
            "interface. A sweep of hosts it cannot observe is not evidence "
            "that those hosts were not swept."
        ),
    },

    # -- Exposed network service -------------------------------------------
    # Every confirmed vulnerability finding lands here or on SSH exposure.
    # An exposure is not an attack: nothing is happening, something is merely
    # reachable. The procedure therefore leads with removing the service and
    # treats firewalling as the fallback, which is the opposite emphasis from
    # the flood guides.
    "MIT-SERVICE-EXPOSURE": {
        "enforcement_point": (
            f"{HOST}, and before that the service itself.\n\n"
            "A service that does not run cannot be reached through a firewall "
            "mistake, so stopping and disabling it is a stronger control than "
            "any rule. Use the firewall for services that have to keep "
            "running but should not be reachable from everywhere.\n\n"
            "The finding records the position the scan was run from. A port "
            "reachable from there may be unreachable from elsewhere, and a "
            "port that looked closed may be open to a different network. The "
            "firewall profile you apply a rule to has to match the network "
            "the host is actually on."
        ),
        "procedure_steps": _steps(
            "Read the finding first. It records the address, the port, the "
            "protocol, the service name Nmap identified, and in the evidence "
            "field the product and version it inferred from the banner. That "
            "version is an inference from what the service advertised, not a "
            "verified fact, so do not act on it alone.",
            "Find out what is actually listening, on the host itself: "
            "Get-NetTCPConnection -State Listen -LocalPort <PORT> | "
            "Select-Object LocalAddress, LocalPort, OwningProcess",
            "Turn that process id into a name, so you know what you are "
            "about to change: Get-Process -Id <the OwningProcess value>",
            "Decide whether the host is supposed to offer this service at "
            "all. An open port is not automatically a vulnerability - a web "
            "server is supposed to listen on 443. The finding is a question "
            "about intent, and only the system owner can answer it.",
            "If the service is not needed, remove it rather than hiding it. "
            "Record its current startup type first, because you cannot roll "
            "back without it: Get-Service -Name <the service name> | "
            "Select-Object Name, Status, StartType",
            "Then stop it and stop it coming back: Stop-Service -Name <the "
            "service name> followed by Set-Service -Name <the service name> "
            "-StartupType Disabled. Do this through your change process, not "
            "in the middle of the working day.",
            f"If the service must keep running but should not be reachable "
            f"from everywhere: {_OPEN_WF}",
            "Select Inbound Rules, then New Rule, then Port. Enter the single "
            "port from the finding under Specific local ports. Do not choose "
            "All local ports.",
            "Finish the rule, then reopen it and use the Scope tab: under "
            "Remote IP address choose These IP addresses and add only the "
            "networks that legitimately need this service. This step is the "
            "mitigation; the rule without it changes nothing.",
            "On the Advanced tab, confirm the profiles match the network this "
            "host is really on. Domain, Private and Public are separate, and "
            "a rule on the wrong profile has no effect.",
            "Equivalent PowerShell, in an Administrator window, with the "
            "address list replaced by your own: New-NetFirewallRule "
            "-DisplayName 'AETHRA-SEC restrict <PORT>' -Direction Inbound "
            "-Action Allow -Protocol <PROTOCOL> -LocalPort <PORT> "
            "-RemoteAddress 192.168.1.0/24 -Profile Domain,Private",
            "Record the product and version from the finding's evidence "
            "against the host, so the next assessment can be compared with "
            "this one rather than read from scratch.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "If you disabled the service, confirm nothing is listening any "
            "more: Get-NetTCPConnection -State Listen -LocalPort <PORT> "
            "should return nothing at all.",
            "If you added a rule, confirm it exists and is enabled: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' | "
            "Select-Object DisplayName, Enabled, Direction, Action",
            "Confirm the scope is what you intended, which is the part most "
            "often wrong: Get-NetFirewallRule -DisplayName 'AETHRA-SEC "
            "restrict <PORT>' | Get-NetFirewallAddressFilter",
            "From a host that SHOULD still reach the service, confirm it "
            "does: Test-NetConnection <TARGET_IP> -Port <PORT> reports "
            "TcpTestSucceeded True.",
            "From a host that should NOT reach it, confirm it no longer can. "
            "Only test from machines you are authorised to test from.",
            "Re-run the assessment against <TARGET_IP> and compare it with "
            "the previous scan on the Vulnerability Assessment history "
            "screen. The finding should be gone, or its risk reduced. If it "
            "is unchanged, the rule did not take effect - check the profile "
            "and the scope before changing anything else.",
        ),
        "rollback_steps": _steps(
            "If you disabled a service and something broke, put it back with "
            "the startup type you recorded: Set-Service -Name <the service "
            "name> -StartupType <the value you recorded> then Start-Service "
            "-Name <the service name>",
            "If you added a rule, disable it first rather than deleting it: "
            "Disable-NetFirewallRule -DisplayName 'AETHRA-SEC restrict <PORT>'",
            "Confirm the affected client works again before going further.",
            "Delete the rule only once you are satisfied it was the cause: "
            "Remove-NetFirewallRule -DisplayName 'AETHRA-SEC restrict <PORT>'",
            "Never disable the firewall as a whole to test this. Disable the "
            "one rule you added, by its name.",
            "Re-run the assessment afterwards so the record reflects what the "
            "host actually exposes now.",
        ),
        "operational_warnings": (
            "An exposure is not an attack. Nothing in this finding says "
            "anyone connected, tried to, or succeeded. It says a service is "
            "reachable.\n\n"
            "An open port is not automatically a vulnerability. Most findings "
            "of this kind are rated low precisely because being reachable and "
            "being exploitable are different things.\n\n"
            "Disabling a service breaks whatever depends on it, and what "
            "depends on it is often not obvious from the host. Virtualisation, "
            "backup, printing and management agents all listen on ports whose "
            "names suggest nothing in particular.\n\n"
            "The product and version in the evidence field come from what the "
            "service advertised about itself. Banners can be wrong, stale or "
            "deliberately misleading, so confirm the version on the host "
            "before concluding anything about its patch level.\n\n"
            "A rule scoped to the wrong firewall profile looks correct in the "
            "console and does nothing on the network. Check the profile "
            "before concluding the mitigation failed.\n\n"
            "The scan reached this port from one position on the network. "
            "That is not evidence about what the rest of the network can "
            "reach, in either direction."
        ),
    },

    # -- SSH exposure -------------------------------------------------------
    # Separate from general service exposure because remote administration is
    # the thing an attacker most wants, and because the host may not be
    # Windows at all - which changes every instruction.
    "MIT-SSH-EXPOSURE": {
        "enforcement_point": (
            "Depends on what the target actually is, and that has to be "
            "settled first.\n\n"
            f"{HOST} can restrict which networks reach 22/tcp if the target "
            "is a Windows host running the OpenSSH Server optional feature. "
            "On this machine that feature is not installed, so do not assume "
            "the target is Windows because AETHRA-SEC runs on Windows.\n\n"
            "If the target is a Linux host, an appliance, a switch or a "
            "router, none of the Windows steps apply and the configuration "
            "lives on that device. Its owner makes the change, not you from "
            "here.\n\n"
            f"{EDGE} is where exposure beyond the campus is removed. SSH "
            "reachable from the public internet is a separate and more urgent "
            "problem than SSH reachable from the next room."
        ),
        "procedure_steps": _steps(
            "Establish what <TARGET_IP> is before touching anything. Check "
            "the host inventory on the Vulnerability Assessment screen for "
            "the hostname and vendor, and the finding's evidence field for "
            "the SSH product and version it advertised. Applying Windows "
            "instructions to a Linux host is how outages happen.",
            "Confirm whether the service is reachable from outside the campus "
            "network, which is the part that decides urgency. Ask whoever "
            "administers the gateway whether 22/tcp reaches <TARGET_IP> from "
            "the internet. Do not test this by scanning from outside - that "
            "is scanning a network you were not authorised to scan.",
            "Establish who is supposed to administer this host over SSH, and "
            "from which networks. Without that answer there is no correct "
            "scope to apply, and a guess locks somebody out.",
            "If the target is a Windows host, check whether it is in fact "
            "running OpenSSH Server: Get-Service -Name sshd will return "
            "nothing if the feature is not installed, in which case something "
            "else is answering on that port and the finding needs "
            "re-examining.",
            "On a Windows target that does run it and should not, remove the "
            "feature rather than firewalling it: Get-WindowsCapability "
            "-Online -Name OpenSSH.Server* to confirm it is present, then "
            "Remove-WindowsCapability with that capability name, through your "
            "change process.",
            f"On a Windows target that must keep SSH: {_OPEN_WF}",
            "Create an inbound Port rule for TCP <PORT>, then use the Scope "
            "tab to restrict Remote IP address to the administrative networks "
            "you identified, for example: New-NetFirewallRule -DisplayName "
            "'AETHRA-SEC restrict SSH' -Direction Inbound -Action Allow "
            "-Protocol TCP -LocalPort <PORT> -RemoteAddress 192.168.1.0/24 "
            "-Profile Domain,Private",
            "If the target is not Windows, stop here and hand the finding to "
            "its owner, with the address, the port, the advertised version "
            "and the networks that should retain access. Ask them to restrict "
            "it at the device and to confirm key-based authentication is in "
            "use. Do not follow configuration instructions for a system you "
            "have not confirmed.",
            "Have the owner, or your gateway administrator, confirm that SSH "
            "is not reachable from the public internet. That is the single "
            "most valuable outcome of this finding.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "If you removed the Windows feature, confirm it is gone: "
            "Get-Service -Name sshd returns nothing, and "
            "Get-NetTCPConnection -State Listen -LocalPort <PORT> returns "
            "nothing.",
            "If you added a rule, confirm it exists and is enabled: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' | "
            "Select-Object DisplayName, Enabled, Direction, Action",
            "Confirm the scope: Get-NetFirewallRule -DisplayName 'AETHRA-SEC "
            "restrict SSH' | Get-NetFirewallAddressFilter",
            "From an administrative host that must retain access, confirm it "
            "still has it: Test-NetConnection <TARGET_IP> -Port <PORT>. Do "
            "this before you log out of your own session.",
            "Re-run the assessment against <TARGET_IP> and compare it with "
            "the previous scan. The finding should be gone or reduced.",
            "If the change was made on a non-Windows device by its owner, ask "
            "them to confirm what they changed, and record it against the "
            "finding. An unrecorded change on somebody else's device is not "
            "verification.",
        ),
        "rollback_steps": _steps(
            "Keep a working session open while you change SSH access. If you "
            "lock yourself out of a remote host, rollback needs physical or "
            "console access, which may not be available.",
            "If you added a rule, disable it by name first: "
            "Disable-NetFirewallRule -DisplayName 'AETHRA-SEC restrict SSH'",
            "Confirm administrative access works again.",
            "Delete it once you are satisfied: Remove-NetFirewallRule "
            "-DisplayName 'AETHRA-SEC restrict SSH'",
            "If a Windows capability was removed, it is reinstalled through "
            "the same Windows optional-features mechanism it was removed "
            "with, and the service then has to be started and set to start "
            "automatically again.",
            "Never disable the firewall as a whole to test this. Disable the "
            "one rule you added, by its name.",
        ),
        "operational_warnings": (
            "Restricting remote administration can lock you out of the host "
            "you are administering. Keep a working session open, and have "
            "console or physical access available, before you apply the "
            "change.\n\n"
            "This finding says the port answered. It does not say anyone "
            "authenticated, or tried to.\n\n"
            "The version string came from what the service advertised. Treat "
            "it as a lead, not as proof of a patch level.\n\n"
            "If AETHRA-SEC is not running on the target, none of the Windows "
            "commands here apply to it. The host firewall you can reach is "
            "the one on this machine.\n\n"
            "Do not verify internet exposure by scanning from an outside "
            "network. That is a scan of infrastructure you were not "
            "authorised to scan; ask the gateway administrator instead.\n\n"
            "Blocking the administrative subnet by mistake is the commonest "
            "way this change goes wrong. Confirm the scope before you rely "
            "on it."
        ),
    },

    # -- TCP SYN flood ------------------------------------------------------
    "MIT-TCP-SYN-FLOOD": {
        "enforcement_point": (
            f"{EDGE} for the traffic volume, and {HOST} only for reducing "
            "exposure.\n\n"
            "This matters more here than anywhere else. Windows Defender "
            "Firewall has NO SYN-flood protection, NO connection rate limiting "
            "and NO SYN proxy - this was checked against the NetSecurity "
            "module, which exposes no such control. A host rule drops the "
            "packets after they have crossed your network link, so it protects "
            "the service but does nothing about saturation. Only a device "
            "upstream of the link can do that."
        ),
        "procedure_steps": _steps(
            "Confirm what is actually being attacked. The alert names "
            "<TARGET_IP> and, where recorded, the destination port. Check on "
            "the target whether something is really listening there: "
            "Get-NetTCPConnection -State Listen -LocalPort <PORT>",
            "Decide whether the service needs to be reachable from the "
            "source's network at all. If it does not, the fix is a scope "
            "restriction and not a block rule.",
            f"{_OPEN_WF}",
            "Select Inbound Rules, then New Rule. Choose Port, then TCP, then "
            "enter the affected port under Specific local ports.",
            "Choose Block the connection if the service should not be reachable "
            "from the source network at all, then Next, then select the "
            "applicable profiles, then name and finish.",
            "If instead the service must stay available to a known set of "
            "clients, create an Allow rule scoped on the Scope tab to those "
            "subnets, and make sure no broader Allow rule already covers the "
            "port. Windows applies the most specific matching rule, and a "
            "pre-existing allow-all rule will mask yours.",
            "Equivalent PowerShell, Administrator window, replacing <PORT> and "
            "<SOURCE_IP>: New-NetFirewallRule -DisplayName "
            "'AETHRA-SEC SYN block <SOURCE_IP>' -Direction Inbound -Action "
            "Block -Protocol TCP -LocalPort <PORT> -RemoteAddress <SOURCE_IP>",
            "NOW ESCALATE. Contact whoever administers the campus gateway or "
            "router and give them the source address, the target address, the "
            "port and the time window from this alert. Ask specifically "
            "whether the device supports SYN-flood protection or connection "
            "rate limiting and whether it can be enabled for this target.",
            "Do not follow vendor instructions you have not confirmed. Ask the "
            "administrator which firewall it is before anyone types anything "
            "into it; the menu path on one vendor is meaningless on another.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "Confirm the rule is live: Get-NetFirewallRule -DisplayName "
            "'AETHRA-SEC*' | Select-Object DisplayName, Enabled, Action",
            "Confirm the service still answers legitimate clients: "
            "Test-NetConnection <TARGET_IP> -Port <PORT> from an address that "
            "should still have access.",
            "Watch AETHRA-SEC's Live Monitoring screen. If the packet rate on "
            "the interface is unchanged after the host rule, that is the "
            "expected result and it confirms the point above: the host rule "
            "protects the service, not the link.",
            "Check whether the episode's current severity falls on the IDS "
            "Alerts screen. Current severity follows the measured rate, so a "
            "genuine reduction shows there.",
            "Treat the threat as mitigated only when the rate falls - which "
            "normally requires the upstream change, not the host rule.",
        ),
        "rollback_steps": _steps(
            "List what you added: Get-NetFirewallRule -DisplayName 'AETHRA-SEC*'",
            "Disable the specific rule: Disable-NetFirewallRule -DisplayName "
            "'AETHRA-SEC SYN block <SOURCE_IP>'",
            "Confirm the service is reachable again from an affected client.",
            "Remove it when you are sure: Remove-NetFirewallRule -DisplayName "
            "'AETHRA-SEC SYN block <SOURCE_IP>'",
            "Ask the network administrator to reverse any upstream change "
            "separately. You cannot undo their change from this host.",
        ),
        "operational_warnings": (
            "Windows Defender Firewall cannot rate-limit and cannot defend "
            "against a flood that saturates the network link. Blocking at the "
            "endpoint keeps the service alive; it does not reduce the traffic "
            "arriving.\n\n"
            "A SYN flood frequently uses spoofed source addresses. Blocking "
            "the address in the alert may block an innocent third party and "
            "have no effect on the attack. Weigh that before using a block "
            "rule.\n\n"
            "Blocking the port blocks it for everyone, including legitimate "
            "users, until you remove the rule.\n\n"
            "Never respond by disabling the firewall or blocking all TCP."
        ),
    },

    # -- UDP flood ----------------------------------------------------------
    "MIT-UDP-FLOOD": {
        "enforcement_point": (
            f"{EDGE} for the volume; {HOST} for closing an unnecessary UDP "
            "service.\n\n"
            "UDP is connectionless, so there is no handshake to refuse. A host "
            "rule stops the datagrams being processed by the service, which "
            "protects the service, but the traffic still arrives on the link."
        ),
        "procedure_steps": _steps(
            "Identify the affected UDP port from the alert. If the alert does "
            "not record a destination port, do NOT guess one - go to step 3 "
            "and identify it from the host instead.",
            "Decide whether that UDP service is one you run deliberately. "
            "Common legitimate UDP services are DNS (53), DHCP (67/68) and "
            "NTP (123); blocking those breaks name resolution, addressing and "
            "time sync respectively.",
            "List what is actually listening on the target: "
            "Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, "
            "OwningProcess",
            "If the service is not needed, stop and disable it. That is a "
            "better fix than a firewall rule.",
            f"If it is needed but over-exposed: {_OPEN_WF}",
            "Inbound Rules, New Rule, Port, UDP, enter the port under Specific "
            "local ports.",
            "Choose Block the connection to refuse it outright, or Allow the "
            "connection and then restrict the Scope tab's Remote IP address "
            "list to the subnets that legitimately use it.",
            "Select the applicable profiles, name the rule, finish.",
            "Equivalent PowerShell, Administrator window: "
            "New-NetFirewallRule -DisplayName 'AETHRA-SEC UDP <PORT>' "
            "-Direction Inbound -Action Block -Protocol UDP -LocalPort <PORT> "
            "-RemoteAddress <SOURCE_IP>",
            "If the traffic volume is the problem rather than the service, "
            "give the network administrator the source, target, port and time "
            "window and ask for filtering at the edge.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "Confirm the rule and its protocol and port: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC UDP <PORT>' | "
            "Get-NetFirewallPortFilter",
            "Confirm the rule is enabled: Get-NetFirewallRule -DisplayName "
            "'AETHRA-SEC UDP <PORT>' | Select-Object Enabled, Action",
            "Test the legitimate service still works. For DNS that is "
            "Resolve-DnsName, for a custom service use its own client. Do not "
            "assume it works because the rule looks right.",
            "Check the UDP share on Live Monitoring's protocol chart before "
            "and after.",
            "Review subsequent AETHRA-SEC alerts for the same source and port.",
        ),
        "rollback_steps": _steps(
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC*' to find it.",
            "Disable-NetFirewallRule -DisplayName 'AETHRA-SEC UDP <PORT>'",
            "Re-test the legitimate service immediately.",
            "Remove-NetFirewallRule -DisplayName 'AETHRA-SEC UDP <PORT>' once "
            "you are satisfied.",
        ),
        "operational_warnings": (
            "Blocking UDP broadly is more disruptive than blocking TCP. DNS, "
            "DHCP and NTP are all UDP, and losing them breaks name resolution, "
            "address assignment and clock sync across the segment.\n\n"
            "UDP source addresses are trivially spoofed, so the source in the "
            "alert may not be the real origin.\n\n"
            "If the alert carries no destination port, a port-specific rule "
            "cannot be written from it. Identify the port on the host first."
        ),
    },

    # -- ICMP flood ---------------------------------------------------------
    "MIT-ICMP-FLOOD": {
        "enforcement_point": (
            f"{HOST} for echo requests specifically; {EDGE} for volume.\n\n"
            "Windows Defender Firewall can filter ICMP by type, which is the "
            "right level of precision here - blocking echo requests while "
            "leaving the rest of ICMP alone."
        ),
        "procedure_steps": _steps(
            "Check the measured rate on the alert before acting. AETHRA-SEC "
            "measures ICMP per source address, so a ping exchange shows as two "
            "detections - one per direction - each at roughly half the rate on "
            "the Traffic Rate graph. Make sure you are reading the right one.",
            "Confirm whether the destination needs to answer pings at all. "
            "Monitoring systems, some clustering software and ordinary "
            "troubleshooting rely on it.",
            f"{_OPEN_WF}",
            "Inbound Rules, New Rule, Custom, then Next.",
            "Leave All programs selected, then Next. On the Protocol and Ports "
            "page set Protocol type to ICMPv4.",
            "Click Customize beside Internet Control Message Protocol settings. "
            "Choose Specific ICMP types and tick only Echo Request. This is the "
            "step that keeps the rule narrow - do not leave All ICMP types "
            "selected.",
            "On the Scope page, under Which remote IP addresses, choose These "
            "IP addresses and add <SOURCE_IP>. A rule scoped to one source is "
            "far safer than one that blocks echo from everywhere.",
            "Choose Block the connection, select the applicable profiles, name "
            "the rule and finish.",
            "Equivalent PowerShell, Administrator window. ICMP type 8 is Echo "
            "Request: New-NetFirewallRule -DisplayName "
            "'AETHRA-SEC ICMP echo <SOURCE_IP>' -Direction Inbound -Action "
            "Block -Protocol ICMPv4 -IcmpType 8 -RemoteAddress <SOURCE_IP>",
            "If the rate is high enough to affect the link rather than the "
            "host, give the network administrator the source, target and time "
            "window and ask for rate limiting at the edge. The host cannot do "
            "this.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "Confirm the rule exists, is enabled, and is scoped to the source: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC ICMP*' | "
            "Select-Object DisplayName, Enabled, Action",
            "Confirm it is restricted to the intended source: "
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC ICMP*' | "
            "Get-NetFirewallAddressFilter",
            "From the source host, in an authorised test, ping the target and "
            "confirm it now times out.",
            "From a DIFFERENT host that should still be able to ping, confirm "
            "it still can. If it cannot, the scope is wrong.",
            "Confirm traceroute and path MTU discovery still behave for normal "
            "users, since both depend on other ICMP types.",
            "Watch the ICMP share on Live Monitoring's protocol chart.",
        ),
        "rollback_steps": _steps(
            "Get-NetFirewallRule -DisplayName 'AETHRA-SEC ICMP*'",
            "Disable-NetFirewallRule -DisplayName "
            "'AETHRA-SEC ICMP echo <SOURCE_IP>'",
            "Ping the target from the affected host to confirm it answers "
            "again.",
            "Remove-NetFirewallRule -DisplayName "
            "'AETHRA-SEC ICMP echo <SOURCE_IP>' when you are satisfied.",
        ),
        "operational_warnings": (
            "Do not block all ICMP. Path MTU discovery depends on "
            "Fragmentation Needed, and losing it causes connections that open "
            "and then hang on larger transfers - an intermittent fault that is "
            "very hard to diagnose later.\n\n"
            "Blocking echo makes the host invisible to ping, which will "
            "confuse anyone troubleshooting it and may make monitoring systems "
            "report it as down.\n\n"
            "ICMP source addresses are easily spoofed.\n\n"
            "A host rule does not reduce the traffic on the link."
        ),
    },

    # -- HTTP flood ---------------------------------------------------------
    "MIT-HTTP-FLOOD": {
        "enforcement_point": (
            f"{WEB} first; {EDGE} for volume. A host firewall is the wrong "
            "tool here.\n\n"
            "An HTTP flood is valid requests arriving too fast. Windows "
            "Defender Firewall works at the packet level: it can allow or "
            "block a port, but it cannot count requests, cannot rate-limit, "
            "and cannot tell one HTTP request from another. Blocking port 80 "
            "or 443 takes the site off the air, which is what the attack "
            "wanted."
        ),
        "procedure_steps": _steps(
            "Confirm it is actually abnormal. Check the web server's own "
            "access log for <TARGET_IP> and compare the request rate with a "
            "normal busy period. A lecture starting, a deadline, or a link "
            "being shared all produce genuine spikes.",
            "Look at what the requests have in common in the access log: one "
            "source address, one URL, one user agent, no referrer. That "
            "pattern is what any rate limit or filter will key on.",
            "If the traffic comes from a small number of verified-hostile "
            "addresses, block those addresses - not the port - at the web "
            "server or reverse proxy, where the block can be specific to the "
            "site.",
            "Enable request rate limiting in whatever actually sits in front "
            "of the site. In IIS this is the Dynamic IP Restrictions module, "
            "if it is installed. In nginx it is limit_req_zone with limit_req. "
            "In Apache it is a module such as mod_ratelimit or mod_evasive. "
            "Confirm which of these you actually run before configuring any of "
            "them - do not follow instructions for a product you do not have.",
            "Only if you must take the service off the air deliberately, and "
            "understand that this is an outage: "
            "New-NetFirewallRule -DisplayName 'AETHRA-SEC HTTP <SOURCE_IP>' "
            "-Direction Inbound -Action Block -Protocol TCP -LocalPort 443 "
            "-RemoteAddress <SOURCE_IP>  - scoped to the source, never to all "
            "addresses.",
            "If the volume saturates the link, no change on this host will "
            "help. Give the network administrator or service provider the "
            "source addresses, the target and the time window.",
            _NAME_IT,
        ),
        "verification_steps": _steps(
            "Watch the web server's access log live and confirm the unwanted "
            "request rate falls.",
            "Load the site yourself from a normal client and confirm it still "
            "serves pages at usual speed. A mitigation that breaks the site is "
            "not a mitigation.",
            "If you added a rate limit, confirm it is rejecting with the "
            "expected status - 429 or 503 depending on the product - rather "
            "than dropping legitimate users.",
            "If you added a firewall rule: Get-NetFirewallRule -DisplayName "
            "'AETHRA-SEC HTTP*' | Select-Object Enabled, Action",
            "Compare AETHRA-SEC HTTP detections before and after.",
        ),
        "rollback_steps": _steps(
            "Remove the rate limit in the product that applies it, by reverting "
            "the specific configuration block you added, and reload that "
            "service.",
            "If you added a firewall rule: Disable-NetFirewallRule "
            "-DisplayName 'AETHRA-SEC HTTP <SOURCE_IP>'",
            "Load the site from an ordinary client and confirm it is served "
            "normally.",
            "Remove-NetFirewallRule -DisplayName "
            "'AETHRA-SEC HTTP <SOURCE_IP>' once you are satisfied.",
        ),
        "operational_warnings": (
            "A Windows firewall rule cannot rate-limit HTTP. If you need "
            "requests per second, it has to be done at the web server, the "
            "reverse proxy or a web application firewall.\n\n"
            "Blocking TCP 80 or 443 is an outage, not a mitigation.\n\n"
            "HTTP floods frequently come from many addresses, so blocking one "
            "achieves little.\n\n"
            "Rate limits set too aggressively will reject real users, and that "
            "looks identical to the attack succeeding.\n\n"
            "Taking the web service down should not be the default response."
        ),
    },
}
