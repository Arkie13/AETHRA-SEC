"""Static configuration seeding (§102, §103).

What is seeded: roles, permissions, role-permission grants, tunable system
settings, and the mitigation knowledge base.

What is **never** seeded: hosts, packets, alerts, vulnerabilities, threats,
incidents, scans or any other security record. A freshly installed AETHRA-SEC
shows zeros because it genuinely has no observations yet (§72).

Seeding is idempotent - re-running it updates built-in descriptions without
overwriting an administrator's edits to values or knowledge-base text.
"""

from __future__ import annotations

from typing import Any

from aethra_sec.config.defaults import ALL_SETTING_SPECS
from aethra_sec.core.permissions import PERMISSION_SPECS, ROLE_DEFINITIONS
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import to_db, utcnow

LOGGER = get_logger("database.seed")


def _setting_value_to_text(value: Any, value_type: str) -> str:
    """Render a default setting value for storage as text."""
    if value_type == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def seed_roles_and_permissions(db: DatabaseManager) -> dict[str, int]:
    """Insert roles, permissions and their grants.

    Returns:
        Mapping of role name to role id.
    """
    now = to_db(utcnow())

    for spec in PERMISSION_SPECS:
        db.execute(
            "INSERT INTO permissions (code, name, description, category) "
            "VALUES (%s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE name = VALUES(name), "
            "description = VALUES(description), category = VALUES(category)",
            (spec.code, spec.name, spec.description, spec.category),
        )

    role_ids: dict[str, int] = {}
    for role_name, definition in ROLE_DEFINITIONS.items():
        db.execute(
            "INSERT INTO roles (name, description, created_at) VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE description = VALUES(description)",
            (role_name, str(definition["description"]), now),
        )
        row = db.query_one("SELECT id FROM roles WHERE name = %s", (role_name,))
        if not row:
            continue
        role_id = int(row["id"])
        role_ids[role_name] = role_id

        permission_codes = tuple(definition["permissions"])  # type: ignore[arg-type]
        if not permission_codes:
            continue
        placeholders = ", ".join(["%s"] * len(permission_codes))
        permission_rows = db.query(
            f"SELECT id FROM permissions WHERE code IN ({placeholders})",
            permission_codes,
        )
        db.execute_many(
            "INSERT INTO role_permissions (role_id, permission_id, granted_at) "
            "VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE granted_at = granted_at",
            [(role_id, int(r["id"]), now) for r in permission_rows],
        )
        # Remove grants that are no longer part of the built-in definition so
        # an upgrade cannot leave a role holding a retired permission.
        db.execute(
            "DELETE rp FROM role_permissions rp "
            "JOIN permissions p ON p.id = rp.permission_id "
            f"WHERE rp.role_id = %s AND p.code NOT IN ({placeholders})",
            (role_id, *permission_codes),
        )

    LOGGER.info("Seeded %d roles and %d permissions.", len(role_ids), len(PERMISSION_SPECS))
    return role_ids


def seed_system_settings(db: DatabaseManager) -> int:
    """Insert tunable settings with their defaults.

    Existing values are preserved: only the description and category are
    refreshed, so an administrator's tuning survives an upgrade.
    """
    now = to_db(utcnow())
    rows = [
        (
            spec.key,
            _setting_value_to_text(spec.default, spec.value_type),
            spec.value_type,
            spec.category,
            spec.description,
            now,
        )
        for spec in ALL_SETTING_SPECS
    ]
    db.execute_many(
        "INSERT INTO system_settings "
        "(setting_key, setting_value, value_type, category, description, updated_at) "
        "VALUES (%s, %s, %s, %s, %s, %s) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description), "
        "category = VALUES(category), value_type = VALUES(value_type)",
        rows,
    )
    LOGGER.info("Seeded %d system settings.", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Mitigation knowledge base (§29, §30, §103)
#
# This is guidance text, not security data. Each entry explains what the
# detection means, why it matters, what to do now, what to do long term, and
# how to verify. AETHRA-SEC never applies any of it automatically (§90).
# ---------------------------------------------------------------------------
_MITIGATIONS: tuple[dict[str, Any], ...] = (
    {
        "code": "MIT-PORT-SCAN",
        "threat_name": "Port Scanning Activity",
        "category": ThreatCategory.PORT_SCAN,
        "severity": Severity.MEDIUM,
        "service": "",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "One source address contacted an unusually large number of "
            "destination ports on one or more hosts within a short interval. "
            "This pattern is characteristic of a port scan, which enumerates "
            "which network services a host exposes."
        ),
        "why": (
            "Port scanning is normally a reconnaissance step: an attacker maps "
            "the exposed services of a host before selecting a target. It can "
            "also be legitimate - an authorised vulnerability scan or an asset "
            "inventory tool produces the same pattern - so the first task is to "
            "establish whether the source was authorised."
        ),
        "immediate": (
            "1. Identify the source host and confirm whether the activity was "
            "authorised (a scheduled scan, an inventory agent, an IT technician).\n"
            "2. If it was not authorised, record the source address, the time "
            "window and the ports contacted as evidence.\n"
            "3. Review which of the contacted ports are actually open, using "
            "the Vulnerability Assessment results for the destination host."
        ),
        "long_term": (
            "1. Restrict unnecessary services so that a scan finds less to work "
            "with; close or firewall ports that have no business requirement.\n"
            "2. Segment the network so that workstations cannot reach "
            "management ports on servers.\n"
            "3. Maintain an allow-list of authorised scanning sources in the "
            "Trusted Hosts configuration so that expected scans are easy to "
            "distinguish from unexpected ones."
        ),
        "verify": (
            "1. Re-run a vulnerability assessment against the destination host "
            "and confirm that only the intended ports are open.\n"
            "2. Watch the Network Monitoring screen for repeat activity from "
            "the same source.\n"
            "3. Confirm that any firewall change you made did not disrupt a "
            "required service."
        ),
    },
    {
        "code": "MIT-HOST-SWEEP",
        "threat_name": "Host Sweep / Network Discovery",
        "category": ThreatCategory.HOST_SWEEP,
        "severity": Severity.MEDIUM,
        "service": "",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "One source address contacted many distinct destination hosts in a "
            "short interval, which is the pattern produced by a network sweep "
            "used to discover which addresses are live."
        ),
        "why": (
            "A sweep tells an attacker which addresses respond, narrowing the "
            "target list before more focused probing. Legitimate monitoring and "
            "asset discovery tools behave identically, so authorisation is the "
            "deciding factor."
        ),
        "immediate": (
            "1. Identify the source host and its owner.\n"
            "2. Determine whether a discovery or monitoring tool runs from that "
            "address on this schedule.\n"
            "3. If the source is unknown, treat the host as suspect and review "
            "what else it has been doing on the Host Detail screen."
        ),
        "long_term": (
            "1. Place monitoring and scanning tools on known, documented "
            "addresses and register them as trusted assets.\n"
            "2. Use network segmentation and host firewalls so that a single "
            "compromised workstation cannot enumerate the whole LAN."
        ),
        "verify": (
            "1. Confirm the sweep stops after the authorised tool's window "
            "closes.\n"
            "2. Check the host inventory for new addresses that appeared during "
            "the sweep."
        ),
    },
    {
        "code": "MIT-SSH-EXPOSURE",
        "threat_name": "SSH Service Exposed",
        "category": ThreatCategory.SERVICE_EXPOSURE,
        "severity": Severity.MEDIUM,
        "service": "ssh",
        "source": EvidenceSource.NMAP,
        "explanation": (
            "A vulnerability assessment found an SSH service listening and "
            "reachable from the scanning position. An open port is not by "
            "itself a vulnerability - it indicates an exposed network service "
            "that should be reviewed."
        ),
        "why": (
            "SSH grants interactive administrative access. Where it is reachable "
            "from a broad network segment it becomes an attractive target for "
            "credential guessing, and any weakness in its authentication "
            "configuration has a high impact."
        ),
        "immediate": (
            "1. Confirm the service is intended to be running on this host.\n"
            "2. Check which networks can reach it and restrict access to "
            "authorised management hosts.\n"
            "3. Review the authentication configuration: disable password "
            "authentication in favour of keys where practical, and disable "
            "direct root login."
        ),
        "long_term": (
            "1. Place administrative services behind a management VLAN or "
            "bastion host.\n"
            "2. Enforce key-based authentication and rotate keys on a schedule.\n"
            "3. Enable rate limiting or connection throttling for repeated "
            "failed authentications.\n"
            "4. Keep the SSH server patched and record the version in the asset "
            "inventory."
        ),
        "verify": (
            "1. Re-run the assessment from an unauthorised network position and "
            "confirm the port is no longer reachable.\n"
            "2. Confirm authorised administrators can still connect.\n"
            "3. Review authentication logs for successful logins after the "
            "change."
        ),
    },
    {
        "code": "MIT-SERVICE-EXPOSURE",
        "threat_name": "Network Service Exposed",
        "category": ThreatCategory.SERVICE_EXPOSURE,
        "severity": Severity.LOW,
        "service": "",
        "source": EvidenceSource.NMAP,
        "explanation": (
            "A vulnerability assessment found a network service listening and "
            "reachable. An open port is not automatically a vulnerability: it "
            "indicates an exposed service whose necessity, configuration and "
            "patch level should be reviewed."
        ),
        "why": (
            "Every reachable service enlarges the attack surface. Services that "
            "are unnecessary, unpatched, or reachable from more of the network "
            "than they need to be are the usual starting point of an intrusion."
        ),
        "immediate": (
            "1. Confirm the service is required on this host.\n"
            "2. If it is not required, plan its removal through your change "
            "process.\n"
            "3. If it is required, restrict which networks can reach it and "
            "record the product and version for patch tracking."
        ),
        "long_term": (
            "1. Maintain a documented baseline of the services each host is "
            "supposed to expose, and compare assessments against it.\n"
            "2. Apply host firewalls by default and open only what is needed.\n"
            "3. Track service versions so that published vulnerabilities can be "
            "matched against the inventory."
        ),
        "verify": (
            "1. Re-run the assessment and compare against the previous scan on "
            "the Vulnerability Assessment history screen.\n"
            "2. Confirm that only intended ports remain open."
        ),
    },
    {
        "code": "MIT-TCP-SYN-FLOOD",
        "threat_name": "Potential TCP SYN Flood",
        "category": ThreatCategory.TCP_SYN_FLOOD,
        "severity": Severity.HIGH,
        "service": "",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "An unusually high rate of TCP SYN packets was observed from one "
            "source, with few or no corresponding SYN/ACK replies. This is the "
            "pattern of a SYN flood, in which half-open connections are used to "
            "exhaust a server's connection table."
        ),
        "why": (
            "A sustained SYN flood can make a service unavailable to legitimate "
            "users. The same pattern also appears during aggressive scanning or "
            "when a server is genuinely unreachable, so confirm the destination "
            "host's state before concluding an attack is in progress."
        ),
        "immediate": (
            "1. Check whether the destination service is still responding to "
            "legitimate clients.\n"
            "2. Record the source address, rate and time window.\n"
            "3. Review firewall and rate-limiting configuration in front of the "
            "affected service.\n"
            "4. Investigate the source/destination relationship before taking "
            "any blocking decision."
        ),
        "long_term": (
            "1. Enable SYN cookies or equivalent connection-protection features "
            "on exposed servers.\n"
            "2. Apply connection rate limiting at the network boundary.\n"
            "3. Capacity-plan critical services and monitor connection table "
            "usage."
        ),
        "verify": (
            "1. Confirm the SYN rate returns to its normal baseline on the "
            "traffic chart.\n"
            "2. Confirm the destination service accepts new connections "
            "normally.\n"
            "3. Review whether the protective setting caused any legitimate "
            "connection failures."
        ),
    },
    {
        "code": "MIT-UDP-FLOOD",
        "threat_name": "UDP Flood Indicator",
        "category": ThreatCategory.UDP_FLOOD,
        "severity": Severity.MEDIUM,
        "service": "",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "An unusually high rate of UDP packets was observed toward one host "
            "or port. UDP is connectionless, so a high rate can saturate a link "
            "or overwhelm a service without any handshake being required."
        ),
        "why": (
            "UDP floods consume bandwidth and processing capacity. Exposed UDP "
            "services such as DNS, NTP and SNMP can also be abused as "
            "amplification reflectors, which makes an exposed UDP service a "
            "risk to third parties as well as to the host itself."
        ),
        "immediate": (
            "1. Identify the destination service and confirm whether it should "
            "be exposed at all.\n"
            "2. Review the traffic volume on the Network Monitoring screen and "
            "record the measured rate.\n"
            "3. Check the destination host's resource usage and service "
            "availability."
        ),
        "long_term": (
            "1. Restrict exposed UDP services to the networks that need them.\n"
            "2. Apply rate limiting for UDP services at the boundary.\n"
            "3. Disable recursion/amplification-prone features on DNS and NTP "
            "services that do not require them."
        ),
        "verify": (
            "1. Confirm the packet rate returns to baseline.\n"
            "2. Re-run a vulnerability assessment to confirm which UDP services "
            "remain reachable."
        ),
    },
    {
        "code": "MIT-ICMP-FLOOD",
        "threat_name": "Excessive ICMP Traffic",
        "category": ThreatCategory.ICMP_FLOOD,
        "severity": Severity.MEDIUM,
        "service": "",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "An unusually high rate of ICMP packets was observed. ICMP is "
            "normally low-volume control traffic, so a sustained high rate is "
            "worth explaining."
        ),
        "why": (
            "High ICMP rates are used for ping floods and for network mapping. "
            "They can also be entirely benign - a monitoring system polling many "
            "hosts, or a misconfigured device - so the source's identity "
            "determines how to read the observation."
        ),
        "immediate": (
            "1. Identify the source and whether it is a monitoring system.\n"
            "2. Check whether the destination remains responsive.\n"
            "3. Record the measured rate and the time window."
        ),
        "long_term": (
            "1. Apply an ICMP rate-limiting policy at the network boundary "
            "rather than blocking ICMP entirely, which breaks path MTU "
            "discovery and diagnostics.\n"
            "2. Document which systems are expected to generate ICMP at volume."
        ),
        "verify": (
            "1. Confirm the ICMP rate returns to its baseline on the protocol "
            "distribution chart.\n"
            "2. Confirm normal diagnostics (ping, traceroute) still work after "
            "any filtering change."
        ),
    },
    {
        "code": "MIT-HTTP-FLOOD",
        "threat_name": "Abnormal HTTP Request Volume",
        "category": ThreatCategory.HTTP_FLOOD,
        "severity": Severity.MEDIUM,
        "service": "http",
        "source": EvidenceSource.PYSHARK,
        "explanation": (
            "An unusually high rate of HTTP requests was observed from one "
            "source toward a web service in the decoded traffic."
        ),
        "why": (
            "High request volume can exhaust application resources even when "
            "network bandwidth is fine, because each request may cost database "
            "queries or rendering work. It may equally be a crawler, a health "
            "check, or a misbehaving client."
        ),
        "immediate": (
            "1. Identify the source and the requested resource pattern.\n"
            "2. Check the web service's own access and error logs for the same "
            "window.\n"
            "3. Confirm the service is still responding to normal users."
        ),
        "long_term": (
            "1. Apply per-client request rate limiting at the web server or "
            "reverse proxy.\n"
            "2. Cache expensive responses.\n"
            "3. Review whether the service needs to be reachable from the "
            "network the requests came from."
        ),
        "verify": (
            "1. Confirm the request rate returns to baseline.\n"
            "2. Confirm response times recover in the application's own "
            "monitoring."
        ),
    },
    {
        "code": "MIT-SUSPICIOUS-PAYLOAD",
        "threat_name": "Suspicious Payload Detected",
        "category": ThreatCategory.SUSPICIOUS_PAYLOAD,
        "severity": Severity.HIGH,
        "service": "",
        "source": EvidenceSource.SNORT,
        "explanation": (
            "An intrusion detection signature matched the content of observed "
            "traffic. The signature describes a payload pattern associated with "
            "known malicious activity."
        ),
        "why": (
            "Content-based signatures fire on the data being carried, not just "
            "on connection patterns, so a match is a stronger indicator than a "
            "rate anomaly. It still requires confirmation: signatures can match "
            "benign traffic that happens to contain the same bytes."
        ),
        "immediate": (
            "1. Open the alert and review the signature identity and the raw "
            "alert evidence.\n"
            "2. Inspect the affected host and its application and security "
            "logs for the same time window.\n"
            "3. Determine whether the destination service actually processed "
            "the payload."
        ),
        "long_term": (
            "1. Keep the destination service patched.\n"
            "2. Keep the Snort rule set updated so signatures reflect current "
            "threats.\n"
            "3. Record confirmed false positives using the alert classification "
            "so recurring noise can be recognised."
        ),
        "verify": (
            "1. Confirm no further alerts for the same signature and source.\n"
            "2. Confirm the affected host shows no unexpected processes, "
            "accounts or outbound connections."
        ),
    },
    {
        "code": "MIT-RECON",
        "threat_name": "Reconnaissance Activity",
        "category": ThreatCategory.RECONNAISSANCE,
        "severity": Severity.LOW,
        "service": "",
        "source": EvidenceSource.CORRELATION,
        "explanation": (
            "Activity consistent with information gathering was observed - "
            "service enumeration, banner collection or repeated probing of a "
            "host's exposed services."
        ),
        "why": (
            "Reconnaissance usually precedes a more focused attempt. Detecting "
            "it early gives time to reduce the exposed surface before it is "
            "used."
        ),
        "immediate": (
            "1. Identify the source and whether it is an authorised asset.\n"
            "2. Review which services responded to the probing.\n"
            "3. Record the activity for correlation with any later events from "
            "the same source."
        ),
        "long_term": (
            "1. Reduce unnecessary service exposure.\n"
            "2. Remove or generalise service banners where the software allows "
            "it.\n"
            "3. Keep an inventory of authorised scanning sources."
        ),
        "verify": (
            "1. Re-run an assessment and confirm the exposed surface matches "
            "the intended baseline.\n"
            "2. Watch for repeat activity from the same source."
        ),
    },
    {
        "code": "MIT-DOS",
        "threat_name": "Denial of Service Indicators",
        "category": ThreatCategory.DENIAL_OF_SERVICE,
        "severity": Severity.HIGH,
        "service": "",
        "source": EvidenceSource.CORRELATION,
        "explanation": (
            "Traffic volume or connection behaviour consistent with a denial of "
            "service condition was observed against a host or service."
        ),
        "why": (
            "Availability is a core security property. A successful denial of "
            "service disrupts operations directly, and is sometimes used to "
            "mask other activity happening at the same time."
        ),
        "immediate": (
            "1. Confirm whether the affected service is still available to "
            "legitimate users.\n"
            "2. Record the measured rates, source addresses and time window.\n"
            "3. Review other alerts in the same window in case the volume is "
            "concealing another action.\n"
            "4. Engage your network team before making any boundary change."
        ),
        "long_term": (
            "1. Apply rate limiting and connection protection at the boundary.\n"
            "2. Ensure critical services have monitored capacity headroom.\n"
            "3. Document an escalation procedure for availability incidents."
        ),
        "verify": (
            "1. Confirm traffic returns to baseline on the dashboard traffic "
            "chart.\n"
            "2. Confirm service availability from a normal client position.\n"
            "3. Review logs for anything that occurred during the disruption."
        ),
    },
    {
        "code": "MIT-POLICY-VIOLATION",
        "threat_name": "Policy Violation",
        "category": ThreatCategory.POLICY_VIOLATION,
        "severity": Severity.LOW,
        "service": "",
        "source": EvidenceSource.SNORT,
        "explanation": (
            "Traffic matched a rule describing activity that is permitted by "
            "the network but not by policy - for example a prohibited protocol "
            "or an unapproved service."
        ),
        "why": (
            "Policy violations are not attacks, but they widen the attack "
            "surface and often indicate unmanaged software or shadow IT."
        ),
        "immediate": (
            "1. Identify the host and its owner.\n"
            "2. Confirm which policy the activity contradicts.\n"
            "3. Record the observation for the asset owner."
        ),
        "long_term": (
            "1. Communicate the policy to the affected users.\n"
            "2. Where possible, enforce the policy technically rather than by "
            "convention."
        ),
        "verify": "1. Confirm the activity stops.\n2. Re-check after one week.",
    },
    {
        "code": "MIT-UNCLASSIFIED",
        "threat_name": "Unclassified Security Event",
        "category": ThreatCategory.UNCLASSIFIED,
        "severity": Severity.LOW,
        "service": "",
        "source": None,
        "explanation": (
            "A security event was recorded that does not match a more specific "
            "category in the mitigation knowledge base."
        ),
        "why": (
            "Unclassified events still deserve review: the absence of a "
            "category means the pattern is unfamiliar to the current rule set, "
            "not that it is harmless."
        ),
        "immediate": (
            "1. Open the incident and review the raw evidence from each "
            "contributing source.\n"
            "2. Identify the hosts involved and whether they are known assets.\n"
            "3. Decide whether the event is expected activity."
        ),
        "long_term": (
            "1. If the pattern recurs and is benign, record it so it can be "
            "recognised.\n"
            "2. If it recurs and is not benign, add a matching mitigation entry "
            "so future occurrences carry proper guidance."
        ),
        "verify": (
            "1. Confirm whether the event repeats.\n"
            "2. Confirm the involved hosts behave normally otherwise."
        ),
    },
)


def seed_mitigation_knowledge(db: DatabaseManager) -> int:
    """Insert the built-in mitigation knowledge base and its threat mapping.

    Built-in entries are inserted once. Administrator edits are preserved on
    re-seed: only rows that do not exist yet are created (§31).

    Returns:
        Number of recommendations present after seeding.
    """
    now = to_db(utcnow())
    inserted = 0

    for entry in _MITIGATIONS:
        existing = db.query_one(
            "SELECT id FROM mitigation_recommendations WHERE code = %s",
            (entry["code"],),
        )
        if existing:
            recommendation_id = int(existing["id"])
        else:
            source = entry["source"]
            recommendation_id = db.insert(
                "INSERT INTO mitigation_recommendations "
                "(code, threat_name, category, severity, applies_to_service, "
                " detection_source, explanation, why_it_matters, "
                " immediate_action, long_term_action, verification_steps, "
                " reference_notes, is_active, is_builtin, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, %s, %s)",
                (
                    entry["code"],
                    entry["threat_name"],
                    str(entry["category"]),
                    str(entry["severity"]),
                    entry["service"],
                    str(source) if source else "",
                    entry["explanation"],
                    entry["why"],
                    entry["immediate"],
                    entry["long_term"],
                    entry["verify"],
                    "",
                    now,
                    now,
                ),
            )
            inserted += 1

        db.execute(
            "INSERT INTO threat_mitigation_mapping "
            "(category, recommendation_id, priority, condition_service, "
            " condition_min_severity, is_active) "
            "VALUES (%s, %s, %s, %s, %s, 1) "
            "ON DUPLICATE KEY UPDATE priority = VALUES(priority)",
            (
                str(entry["category"]),
                recommendation_id,
                10 if entry["service"] else 100,
                entry["service"],
                "",
            ),
        )

    total = int(
        db.query_value("SELECT COUNT(*) AS c FROM mitigation_recommendations", default=0)
    )
    LOGGER.info(
        "Mitigation knowledge base: %d new entries, %d total.", inserted, total
    )
    return total


def seed_all(db: DatabaseManager) -> dict[str, int]:
    """Run every seeding step.

    Returns:
        Counts for the first-run summary. No security records are created.
    """
    roles = seed_roles_and_permissions(db)
    settings_count = seed_system_settings(db)
    mitigation_count = seed_mitigation_knowledge(db)
    return {
        "roles": len(roles),
        "permissions": len(PERMISSION_SPECS),
        "settings": settings_count,
        "mitigation_recommendations": mitigation_count,
    }
