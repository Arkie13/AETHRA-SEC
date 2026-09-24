"""Schema creation and migration.

The runner is deliberately simple and forward-only: each migration has an
integer version and is applied exactly once, recorded in ``schema_migrations``.
Adding a future migration means appending a :class:`Migration` to
:data:`MIGRATIONS` - existing installations then upgrade on next start.

Nothing here seeds security data. Only structure is created; static
configuration is handled by :mod:`aethra_sec.database.seed` (§102).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from aethra_sec.config.settings import DatabaseSettings
from aethra_sec.core.errors import SchemaError
from aethra_sec.database.connection import (
    MYSQL_AVAILABLE,
    MYSQL_IMPORT_ERROR,
    DatabaseManager,
)
from aethra_sec.database.schema import CREATE_TABLE_STATEMENTS, REQUIRED_TABLES
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import to_db, utcnow

LOGGER = get_logger("database.migrations")

_IDENTIFIER_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


@dataclass(frozen=True)
class Migration:
    """One forward-only schema migration."""

    version: int
    name: str
    apply: Callable[[DatabaseManager], None]


def _apply_initial_schema(db: DatabaseManager) -> None:
    """Create every table in dependency order."""
    for table_name, ddl in CREATE_TABLE_STATEMENTS:
        LOGGER.debug("Creating table if missing: %s", table_name)
        db.execute(ddl)


def _apply_password_recovery(db: DatabaseManager) -> None:
    """Add the administrator-reviewed password recovery queue.

    Existing installations gain the table without touching any account data;
    a fresh installation already created it in migration 1 and the DDL is
    idempotent, so this runs safely in both directions.
    """
    from aethra_sec.database.schema import PASSWORD_RESET_REQUESTS

    db.execute(PASSWORD_RESET_REQUESTS)


def _column_exists(db: DatabaseManager, table: str, column: str) -> bool:
    """True when a column is already present in the connected schema."""
    return bool(
        db.query_value(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s "
            "AND column_name = %s",
            (table, column),
            default=0,
        )
    )


def _apply_incident_read_state(db: DatabaseManager) -> None:
    """Record when an incident was first opened, for the unread counter.

    The sidebar counter previously showed every open incident, so triaging one
    never changed it. Storing when an incident was first read lets the counter
    mean what a badge should mean: how many incidents nobody has looked at yet.

    Existing rows keep ``viewed_at IS NULL`` and so count as unread, which is
    the truthful starting state - the application has no record of anyone
    having opened them.
    """
    if not _column_exists(db, "incidents", "viewed_at"):
        db.execute(
            "ALTER TABLE incidents "
            "ADD COLUMN viewed_at DATETIME(6) NULL AFTER evaluated_at, "
            "ADD COLUMN viewed_by INT UNSIGNED NULL AFTER viewed_at, "
            "ADD KEY ix_incidents_viewed (viewed_at, status), "
            "ADD CONSTRAINT fk_incidents_viewer "
            "FOREIGN KEY (viewed_by) REFERENCES users (id) ON DELETE SET NULL"
        )


def _apply_hostname_lookup_state(db: DatabaseManager) -> None:
    """Record when reverse DNS was last attempted for a host.

    Capture sees an address and a MAC on the wire; it cannot see a hostname.
    Without a record of the attempt, an empty ``hostname`` means two different
    things - "nobody has looked yet" and "looked, and this address has no DNS
    record" - and the inventory cannot tell an operator which. It also means a
    background resolver would query the same nameless addresses forever.

    Existing rows keep ``hostname_checked_at IS NULL``, which is the truthful
    starting state: no lookup has been recorded for any of them.
    """
    if not _column_exists(db, "hosts", "hostname_checked_at"):
        db.execute(
            "ALTER TABLE hosts "
            "ADD COLUMN hostname_checked_at DATETIME(6) NULL AFTER hostname, "
            "ADD KEY ix_hosts_hostname_checked (hostname_checked_at)"
        )


def _apply_os_detail_columns(db: DatabaseManager) -> None:
    """Record the version and CPE an OS discovery reported.

    ``os_name`` alone loses the two things that make a fingerprint actionable:
    which build it is, and the CPE that ties it to published vulnerabilities.
    Both are reported by Nmap's OS match and by ``smb-os-discovery``, and both
    were being discarded for want of a column.

    Existing rows keep empty strings, which is the truthful starting state -
    nothing was recorded for them.
    """
    for table in ("hosts", "scan_hosts"):
        if not _column_exists(db, table, "os_version"):
            db.execute(
                f"ALTER TABLE {table} "
                "ADD COLUMN os_version VARCHAR(96) NOT NULL DEFAULT '' "
                "AFTER os_name, "
                "ADD COLUMN os_cpe VARCHAR(190) NOT NULL DEFAULT '' "
                "AFTER os_version"
            )


def _apply_anomaly_detected_at(db: DatabaseManager) -> None:
    """Record when a rule fired, separately from when its row was written.

    Detection latency could previously only be computed as ``first_seen`` to
    ``created_at``, which conflates the rule's own counting window with the
    time taken to persist. With ``detected_at`` the three intervals separate:
    capture to detection, detection to persistence, and the window span.

    Existing rows keep NULL, which is truthful - the instant was not recorded
    for them and must not be guessed at from ``created_at``.
    """
    if not _column_exists(db, "traffic_anomalies", "detected_at"):
        db.execute(
            "ALTER TABLE traffic_anomalies "
            "ADD COLUMN detected_at DATETIME(6) NULL AFTER window_seconds"
        )


def _apply_anomaly_review_marker(db: DatabaseManager) -> None:
    """Give an anomaly a read receipt that is not a classification.

    The Alerts screen counts a detection as unreviewed until an analyst has
    triaged it, and offers "Mark all reviewed" to clear that counter. For a
    Snort alert the marker is its NEW status. AETHRA-SEC's own detections had
    no equivalent, so the counter was read from ``evaluation`` instead - and
    clearing it in bulk would have meant writing an analyst's judgement.

    ``EvaluationLabel`` is documented as applied by an authorised evaluator and
    never assigned automatically, and those labels are the input to the
    detection-accuracy statistics. Stamping them in bulk would corrupt the
    measurement the labels exist to support, so review state gets its own two
    columns and the evaluation is left to the analyst.

    Existing rows keep NULL: nobody has reviewed them, which is the truth.
    """
    if not _column_exists(db, "traffic_anomalies", "reviewed_at"):
        db.execute(
            "ALTER TABLE traffic_anomalies "
            "ADD COLUMN reviewed_at DATETIME(6) NULL AFTER detected_at, "
            "ADD COLUMN reviewed_by INT UNSIGNED NULL AFTER reviewed_at"
        )


#: Mitigation entries for categories the study does not test. Both were seeded
#: by this application, never authored by an operator, and neither category can
#: be produced by any detection rule AETHRA-SEC has.
_OUT_OF_SCOPE_MITIGATIONS = ("MIT-BRUTE-FORCE", "MIT-MALWARE-INDICATOR")


def _apply_scope_alignment(db: DatabaseManager) -> None:
    """Retire mitigation entries outside the study's tested attack scope.

    The manuscript defines five simulated attack scenarios - port scanning,
    TCP SYN flooding, UDP flooding, ICMP flooding and HTTP flooding. Brute
    force and malware appear in its background and literature only. Neither was
    ever a scenario, and neither could be produced by AETHRA-SEC's detection
    engine: both existed solely as keyword buckets used to classify the text of
    an incoming Snort signature.

    This is a *seed-data* removal, not an evidence removal, and it refuses to
    become one. A row is deleted only when all three hold:

    1. no incident references it, so no investigation loses its guidance;
    2. no detection record carries the category, so no observation is orphaned;
    3. ``created_by`` and ``updated_by`` are both NULL, proving the row is
       still the untouched seed and not something an administrator wrote.

    A row failing any of these is left exactly where it is and the reason is
    logged. An operator's work and a real observation both outrank a scope
    correction; the audit trail is never rewritten to tidy a catalogue.
    """
    for code in _OUT_OF_SCOPE_MITIGATIONS:
        row = db.query_one(
            "SELECT id, category, created_by, updated_by "
            "FROM mitigation_recommendations WHERE code = %s",
            (code,),
        )
        if not row:
            continue

        if row["created_by"] is not None or row["updated_by"] is not None:
            LOGGER.warning(
                "Keeping %s: it has been edited by an administrator "
                "(created_by=%s, updated_by=%s), so it is no longer seed data.",
                code, row["created_by"], row["updated_by"],
            )
            continue

        linked = db.query_value(
            "SELECT COUNT(*) FROM incidents WHERE mitigation_id = %s",
            (row["id"],),
            default=0,
        )
        if linked:
            LOGGER.warning(
                "Keeping %s: %s incident(s) reference it as their guidance.",
                code, linked,
            )
            continue

        observed = 0
        for table in ("traffic_anomalies", "incidents"):
            observed += int(
                db.query_value(
                    f"SELECT COUNT(*) FROM {table} WHERE category = %s",
                    (row["category"],),
                    default=0,
                )
                or 0
            )
        if observed:
            LOGGER.warning(
                "Keeping %s: %s stored record(s) carry the %s category, and "
                "real evidence keeps its guidance.",
                code, observed, row["category"],
            )
            continue

        db.execute("DELETE FROM mitigation_recommendations WHERE id = %s", (row["id"],))
        LOGGER.info("Retired out-of-scope mitigation %s (unreferenced seed row).", code)


def _apply_assessment_queue(db: DatabaseManager) -> None:
    """Give a host an assessment state, and a scan the reason it ran.

    Automatic assessment needs to know, per host, whether it has been assessed
    and when - otherwise every packet from a known host would re-queue it, and
    a restart would rescan the whole network. Holding that in memory would lose
    it on restart and let two workers disagree, so it lives beside the host.

    ``trigger_source`` records what caused a scan. It is not named ``trigger``
    because that is a reserved word in MySQL.

    Existing rows are left DISCOVERED with no assessment time, which is the
    truth: they were observed before automatic assessment existed, and nothing
    should claim they were assessed.
    """
    if not _column_exists(db, "hosts", "assessment_state"):
        db.execute(
            "ALTER TABLE hosts "
            "ADD COLUMN assessment_state VARCHAR(16) NOT NULL "
            "DEFAULT 'DISCOVERED' AFTER discovery_source, "
            "ADD COLUMN last_assessed_at DATETIME(6) NULL AFTER assessment_state, "
            "ADD COLUMN assessment_attempts INT UNSIGNED NOT NULL DEFAULT 0 "
            "AFTER last_assessed_at, "
            "ADD COLUMN last_scan_id BIGINT UNSIGNED NULL AFTER assessment_attempts, "
            "ADD KEY ix_hosts_assessment (assessment_state, last_assessed_at)"
        )
    if not _column_exists(db, "scans", "trigger_source"):
        db.execute(
            "ALTER TABLE scans "
            "ADD COLUMN trigger_source VARCHAR(24) NOT NULL DEFAULT 'MANUAL' "
            "AFTER profile_label, "
            "ADD KEY ix_scans_trigger (trigger_source)"
        )


def _apply_offlink_mac_correction(db: DatabaseManager) -> None:
    """Clear MAC addresses recorded against hosts that cannot own them.

    A frame arriving from outside the local network carries the *gateway's*
    source MAC, not the remote machine's - the remote machine's address never
    appears on this link at all. An earlier version of the capture pipeline
    stored that source MAC against whichever IP the frame carried, so the
    router's hardware address ended up attached to hundreds of unrelated
    internet endpoints. On this installation one MAC was recorded against 528
    distinct public addresses, which is by itself the proof: a MAC identifies
    exactly one interface.

    The capture pipeline no longer does this - it attaches a MAC only when the
    address is on a network the sensor is attached to - but the rows it wrote
    before that remain, and Host Inventory presents them as observed hardware
    identity.

    What this corrects and what it does not:

    * Only the ``mac_address`` field is cleared, and only on addresses outside
      RFC1918 and the other non-routable ranges. Such an address cannot be on
      a laboratory link, so a MAC recorded against it is provably not its own.
    * No row is deleted. The observation that this address was contacted is
      real and stays, with its timestamps, source and traffic history intact.
    * Nothing is invented in the cleared field's place. An unknown MAC reads
      as unknown, which is what the interface already renders as
      "not observed". The column is NOT NULL with an empty default, so
      the empty string - not NULL - is this schema's "no MAC observed".
    * On-link hosts are untouched, including any private address, because
      there a directly observed MAC is genuine evidence.
    """
    db.execute(
        "UPDATE hosts SET mac_address = '', "
        "updated_at = updated_at "
        "WHERE mac_address IS NOT NULL AND mac_address <> '' "
        "AND ip_address NOT LIKE '192.168.%' "
        "AND ip_address NOT LIKE '10.%' "
        "AND ip_address NOT LIKE '172.16.%' AND ip_address NOT LIKE '172.17.%' "
        "AND ip_address NOT LIKE '172.18.%' AND ip_address NOT LIKE '172.19.%' "
        "AND ip_address NOT LIKE '172.2_.%' "
        "AND ip_address NOT LIKE '172.30.%' AND ip_address NOT LIKE '172.31.%' "
        "AND ip_address NOT LIKE '127.%' "
        "AND ip_address NOT LIKE '169.254.%'"
    )


def _apply_group_mac_correction(db: DatabaseManager) -> None:
    """Clear group MAC addresses recorded as a host's own hardware identity.

    IEEE 802 reserves bit 0 of the first octet as the individual/group bit.
    When it is set the address names a *set* of receivers - broadcast or
    multicast - and by definition belongs to no single interface. So a host
    row carrying ``ff:ff:ff:ff:ff:ff`` is not reporting weak evidence; it is
    reporting something that cannot be true.

    These rows came from the same pipeline defect that
    :func:`_apply_offlink_mac_correction` addresses, seen from the other side:
    the destination MAC of an ARP request or other broadcast frame was stored
    against the address the frame named. That address is usually a genuine
    on-link neighbour, which is why the earlier correction leaves it alone -
    the *host* is real, only its recorded hardware identity is not.

    As with that correction, only the field is cleared. The row, its
    timestamps, its observations and its traffic history all remain, and
    nothing is substituted for the value removed.
    """
    db.execute(
        # MOD(), not the "%" operator: this SQL travels through a driver
        # whose parameter marker is "%s", and a bare percent sign in a
        # statement is a hazard there for no gain.
        "UPDATE hosts SET mac_address = '', updated_at = updated_at "
        "WHERE mac_address <> '' "
        "AND MOD(CONV(SUBSTRING(mac_address, 1, 2), 16, 10), 2) = 1"
    )


def _apply_per_user_notification_reads(db: DatabaseManager) -> None:
    """Give each reader their own record of what they have read.

    ``notifications.user_id`` is nullable, and a NULL means *broadcast* - a
    notification everyone can see. Visibility honoured that from the start;
    read state did not. ``is_read`` is one flag on the shared row, so the first
    analyst to open the panel marked the queue read for every other analyst and
    for the administrator. On this installation all 848 notifications are
    broadcasts, so the flaw applied to every one of them, security alerts
    included - a dismissal by one person could hide a pending alert from
    everybody else.

    Read state is per reader, so it belongs in its own table rather than on the
    notification. The row now carries what happened; who has seen it is
    recorded beside it.

    The existing ``is_read`` column is deliberately left in place and left
    populated. It is the honest record of what was dismissed *before* per-user
    tracking existed, and it cannot be redistributed into per-user rows without
    inventing an attribution nobody recorded - there is no data saying which
    account dismissed those 819 notifications. So it is grandfathered: a
    notification already flagged read stays read for everyone, and every read
    from now on is attributed. Nothing is deleted and nothing is invented.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS notification_reads ("
        "notification_id BIGINT UNSIGNED NOT NULL, "
        "user_id INT UNSIGNED NOT NULL, "
        "read_at DATETIME(6) NOT NULL, "
        "PRIMARY KEY (notification_id, user_id), "
        "KEY ix_notification_reads_user (user_id), "
        "CONSTRAINT fk_notification_reads_notification "
        "FOREIGN KEY (notification_id) REFERENCES notifications (id) "
        "ON DELETE CASCADE, "
        "CONSTRAINT fk_notification_reads_user "
        "FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    )


def _apply_enable_auto_assessment(db: DatabaseManager) -> None:
    """Adopt the automated-by-default posture on an existing installation.

    Automatic assessment now ships on: a host observed inside the authorised
    networks is assessed without an operator typing its address. A fresh
    install gets that from the seeded default. An installation seeded while the
    setting defaulted off still holds the old stored ``false``, and seeding
    never overwrites a stored value - so this one-time migration flips that
    stored value to ``true``.

    It changes *only* a value still equal to the old default. It scans nothing
    on its own: the authorised-network boundary still applies, and the toggle
    on the Vulnerability Assessment screen still turns it off. This runs before
    seeding, so on a brand-new database there is no row yet and this is a no-op;
    seeding then inserts the new default.
    """
    try:
        db.execute(
            "UPDATE system_settings SET setting_value = 'true' "
            "WHERE setting_key = 'assessment.auto_enabled' "
            "AND setting_value = 'false'"
        )
    except Exception:  # noqa: BLE001 - a missing table means a fresh DB; seed handles it
        LOGGER.debug("Could not adopt the automatic-assessment default.", exc_info=True)


def _apply_manuscript_alignment_rev9(db: DatabaseManager) -> None:
    """Structure for the rev9 manuscript alignment.

    * ``hosts.assessment_detail`` / ``hosts.last_attempt_at`` - why a host is
      in its assessment state, and when automation last tried, so a refusal is
      shown rather than re-guessed and a failed host backs off instead of being
      retried every minute.
    * ``scan_findings.cvss_base_score`` / ``cvss_source`` and
      ``vuln_knowledge.cvss_base_score`` - §3.9.9 classifies hosts on CVSS
      v3.1. The columns are nullable and nothing back-fills them: existing
      findings have no score because no source ever supplied one, and that
      stays true.
    * ``evaluation_runs`` / ``evaluation_run_detections`` - §3.9.2 defines
      detection time as alert generation minus *attack initiation*, and the
      application had no record of when an attack was initiated. The tables
      hold that record; every figure computed from them comes from real runs.

    Structure only. No stored value is changed.
    """
    from aethra_sec.database.schema import EVALUATION_RUN_DETECTIONS, EVALUATION_RUNS

    if not _column_exists(db, "hosts", "assessment_detail"):
        db.execute(
            "ALTER TABLE hosts "
            "ADD COLUMN assessment_detail VARCHAR(255) NOT NULL DEFAULT '' "
            "AFTER assessment_attempts, "
            "ADD COLUMN last_attempt_at DATETIME(6) NULL AFTER assessment_detail"
        )
    if not _column_exists(db, "scan_findings", "cvss_base_score"):
        db.execute(
            "ALTER TABLE scan_findings "
            "ADD COLUMN cvss_base_score DECIMAL(3,1) NULL AFTER risk_rationale, "
            "ADD COLUMN cvss_source VARCHAR(64) NOT NULL DEFAULT '' "
            "AFTER cvss_base_score"
        )
    if not _column_exists(db, "vuln_knowledge", "cvss_base_score"):
        db.execute(
            "ALTER TABLE vuln_knowledge "
            "ADD COLUMN cvss_base_score DECIMAL(3,1) NULL AFTER risk_level"
        )
    db.execute(EVALUATION_RUNS)
    db.execute(EVALUATION_RUN_DETECTIONS)


#: Seeded flood thresholds before the rev9 alignment -> the manuscript's §3.9.8
#: values. UDP (300) already matched.
_FLOOD_THRESHOLD_UPGRADES: tuple[tuple[str, str, str], ...] = (
    ("detection.icmp_packets_per_second", "50", "120"),
    ("detection.tcp_syn_per_second", "100", "200"),
    ("detection.http_requests_per_second", "80", "10"),
)


def _apply_manuscript_flood_thresholds(db: DatabaseManager) -> None:
    """Adopt the manuscript's §3.9.8 flood detection thresholds.

    rev9 of the manuscript defines them: 200 pps TCP SYN, 300 pps UDP, 120 pps
    ICMP and 600 HTTP requests per minute. The seeded values predated that
    (ICMP 50, SYN 100, HTTP 80 per second), and seeding never overwrites a
    stored value.

    Only a value still equal to the old seeded default is changed. A threshold
    an administrator tuned is theirs and is left exactly as it is. No stored
    detection record is touched - past anomalies keep the thresholds and
    severities they were raised under, which their evidence records.
    """
    for key, old, new in _FLOOD_THRESHOLD_UPGRADES:
        try:
            changed = db.execute(
                "UPDATE system_settings SET setting_value = %s "
                "WHERE setting_key = %s AND setting_value = %s",
                (new, key, old),
            )
        except Exception:  # noqa: BLE001 - a missing table means a fresh DB
            LOGGER.debug("Could not adopt the §3.9.8 threshold for %s.", key, exc_info=True)
            continue
        if changed:
            LOGGER.info(
                "Adopted manuscript §3.9.8 threshold %s: %s -> %s.", key, old, new
            )


def _index_exists(db: DatabaseManager, table: str, index: str) -> bool:
    """True when a named index is already present on a table."""
    return bool(
        db.query_value(
            "SELECT COUNT(*) FROM information_schema.statistics "
            "WHERE table_schema = DATABASE() AND table_name = %s "
            "AND index_name = %s",
            (table, index),
            default=0,
        )
    )


def _apply_traffic_topsource_index(db: DatabaseManager) -> None:
    """Add the covering index the dashboard's top-sources panel needs.

    The panel groups every packet in the reporting window by source address.
    Without a covering index the optimiser ranges on ``captured_at`` and then
    reads each matching row for ``src_ip``, which was measured near 1.9s over
    100k+ rows and saturated the connection pool on every dashboard refresh.
    ``(captured_at, src_ip, length)`` lets the group be answered from the index
    alone (~0.8s). Structure only; no row is read or written.
    """
    if not _index_exists(db, "traffic_records", "ix_traffic_period_src"):
        try:
            db.execute(
                "ALTER TABLE traffic_records "
                "ADD INDEX ix_traffic_period_src (captured_at, src_ip, length)"
            )
        except Exception:  # noqa: BLE001 - a missing table means a fresh DB
            LOGGER.debug("Could not add the top-source index.", exc_info=True)


def _apply_host_provenance(db: DatabaseManager) -> None:
    """Record where each host came from, and stop claiming what is not known.

    Three defects are corrected here, all of them about the inventory
    asserting more than it observed.

    **The column defaulted to PYSHARK.** Any row inserted without naming a
    source was stamped as a packet-capture discovery. That is a fabricated
    provenance - the one thing the inventory must never produce, because the
    column exists precisely to answer "why is this address here?". The default
    becomes LEGACY, which claims nothing, and every caller now states its
    source explicitly.

    **Addresses that no device owns were enrolled as hosts.** On this
    installation: 45 IPv6 multicast groups, 117 ``fe80::`` link-local
    addresses, 12 IPv4 broadcast/multicast addresses and the unspecified
    address. These are marked, not deleted - they are a true record of what
    appeared on the wire, they simply are not hosts.

    **A /24 was enrolled from ARP destinations.** An earlier capture pipeline
    entered an address it had merely seen *named* by another device. When some
    device swept 192.168.1.0/24, all 256 addresses became "hosts" in about
    seven seconds, in ascending order, most with no MAC. The pipeline was
    fixed - an address must now be seen transmitting, on-link - but the rows
    remain, and they are indistinguishable from real hosts in the interface.

    How the rows are classified, using only evidence still in this database:

    * a stored MAC, or traffic where the address is the *source*, or an alert
      it raised, or a scan it answered -> a real observation; the recorded
      source is kept and described;
    * otherwise -> LEGACY, described as a destination-only sighting.

    Nothing is deleted and no timestamp is altered: ``first_seen``,
    ``last_seen``, assessments and findings are all retained (§20). A LEGACY
    row keeps its history and stops claiming to be a discovered device.

    The classification is deliberately conservative in one direction. Traffic
    retention is short - about eleven hours here against an inventory going
    back weeks - so a host that genuinely transmitted long ago may no longer
    have traffic proving it. That is why a stored MAC alone is accepted as
    evidence: it is only ever recorded for an on-link sender.
    """
    if not _column_exists(db, "hosts", "discovery_interface"):
        db.execute(
            "ALTER TABLE hosts "
            "ADD COLUMN discovery_interface VARCHAR(190) NOT NULL DEFAULT '' "
            "  AFTER discovery_source, "
            "ADD COLUMN discovery_detail VARCHAR(190) NOT NULL DEFAULT '' "
            "  AFTER discovery_interface"
        )
    try:
        db.execute(
            "ALTER TABLE hosts ALTER COLUMN discovery_source SET DEFAULT 'LEGACY'"
        )
    except Exception:  # noqa: BLE001 - a fresh schema already has it
        LOGGER.debug("Could not reset the discovery_source default.", exc_info=True)

    # Addresses no single device can own. Marked, never deleted.
    db.execute(
        "UPDATE hosts SET discovery_source = 'LEGACY', "
        "  discovery_detail = 'not a host address (multicast, broadcast, "
        "link-local or unspecified)' "
        "WHERE discovery_detail = '' AND ("
        "  ip_address LIKE 'ff%:%' OR ip_address LIKE 'fe80::%' "
        "  OR ip_address LIKE '169.254.%' OR ip_address IN ('::', '0.0.0.0', '') "
        "  OR ip_address LIKE '224.%' OR ip_address LIKE '239.%' "
        "  OR ip_address = '255.255.255.255')"
    )

    # Rows with a real observation behind them keep their recorded source.
    db.execute(
        "UPDATE hosts SET discovery_detail = 'observed on link (MAC recorded)' "
        "WHERE discovery_detail = '' AND mac_address <> ''"
    )
    try:
        db.execute(
            "UPDATE hosts h SET h.discovery_detail = 'observed transmitting' "
            "WHERE h.discovery_detail = '' AND EXISTS ("
            "  SELECT 1 FROM traffic_records t WHERE t.src_ip = h.ip_address)"
        )
        db.execute(
            "UPDATE hosts h SET h.discovery_detail = 'raised an IDS alert' "
            "WHERE h.discovery_detail = '' AND EXISTS ("
            "  SELECT 1 FROM snort_alerts a WHERE a.src_ip = h.ip_address)"
        )
        db.execute(
            "UPDATE hosts h SET h.discovery_detail = 'answered a scan probe' "
            "WHERE h.discovery_detail = '' AND EXISTS ("
            "  SELECT 1 FROM scan_hosts s "
            "  WHERE s.host_id = h.id AND s.status = 'up')"
        )
    except Exception:  # noqa: BLE001 - a fresh database has no evidence tables
        LOGGER.debug("Could not read host evidence tables.", exc_info=True)

    # Whatever is left was never seen transmitting and has no MAC: the
    # address was named on the wire by something else.
    db.execute(
        "UPDATE hosts SET discovery_source = 'LEGACY', "
        "  discovery_detail = 'destination-only sighting; no transmission "
        "ever observed' "
        "WHERE discovery_detail = ''"
    )

    # A note the assessment queue wrote while the host was offline, left
    # behind when the host came back. The row then read "Host: UP" beside
    # "offline: not observed recently". The write path now clears it on the
    # transition; these are the ones already stranded.
    db.execute(
        "UPDATE hosts SET assessment_detail = '' "
        "WHERE status <> 'DOWN' AND assessment_detail LIKE '%offline%'"
    )


def _apply_no_response_assessment_state(db: DatabaseManager) -> None:
    """Separate "the scan finished" from "the host answered it".

    The assessment lifecycle had no way to say that Nmap ran to completion and
    the host never replied. ``_reap_finished`` read only the scan row's status,
    so a clean scan against a silent address settled the host as COMPLETED -
    and the inventory then showed

        Host: OFFLINE   Assessment: COMPLETED   Open ports: 0   Findings: 0

    which reads as a host that was examined and found clean. It was not
    examined at all. On this installation that affected the rows corrected
    below.

    What is corrected is only the host's cached lifecycle label, which is
    derived state. **No scan, finding or observation is altered or removed**:
    every ``scans`` row keeps its own status, timings, command line and
    ``hosts_up`` count, and the correction is computed *from* that evidence.
    A host whose last scan completed with ``hosts_up >= 1`` keeps COMPLETED.

    The security result is unaffected either way - ``derive_security_result``
    already refused to call an unanswered scan Safe - so this changes what the
    assessment column says, not any security conclusion.
    """
    # COMPLETED and COOLDOWN both assert the host was examined. Re-decide them
    # against the scan that produced them; leave every other state alone.
    db.execute(
        "UPDATE hosts h JOIN scans s ON s.id = h.last_scan_id "
        "SET h.assessment_state = %s, "
        "h.assessment_detail = CONCAT('scan ', s.id, ' completed; the host "
        "did not answer, so nothing was examined'), "
        "h.updated_at = %s "
        "WHERE h.assessment_state IN ('COMPLETED', 'COOLDOWN') "
        "AND s.status = 'COMPLETED' AND COALESCE(s.hosts_up, 0) <= 0",
        # Literal, not the enum: a migration records what was done at the time
        # it ran, and must not change meaning if the enum is later edited.
        ("NO_RESPONSE", to_db(utcnow())),
    )
    # Deliberately *not* done here: back-filling a reason onto the ~1,700
    # hosts that are SKIPPED with an empty ``assessment_detail``. Those rows
    # were skipped by earlier migrations that did not record why, and the
    # reason cannot be reconstructed from the evidence. Writing a uniform
    # sentence into all of them would put text in the database that describes
    # nothing, so the absence is reported at display time instead - see
    # ``Host.assessment_reason_text``.


def _apply_supersede_stale_findings(db: DatabaseManager) -> None:
    """Close findings an assessment has since stopped observing.

    A finding records what one assessment saw. Nothing closed the previous
    assessment's findings, so every completed scan added a fresh set and each
    host accumulated the union of everything it had ever exposed. On this
    installation that showed as an exposure panel listing the same four ports
    five times - once per scan - under the heading "20 open services", beside
    a status line reporting the latest scan had found four.

    One host was worse than duplicated: it held eleven open findings while its
    most recent answered assessment found none, presenting exposure that had
    been withdrawn as though it were current.

    The write path now supersedes on each new answered scan. This settles the
    rows already accumulated, by the same rule:

        close a host's open findings from assessments *older* than the most
        recent scan of that host which COMPLETED and which the host answered
        (``hosts_up >= 1``).

    The guard matters. A scan the host did not answer observed nothing, so it
    must never close known exposure - otherwise one unanswered probe would
    erase a real finding.

    **Nothing is deleted.** Every row keeps its scan id, its evidence, its
    rating, its CVSS score and its timestamps, and stays readable through the
    scan it belongs to. What changes is that it stops counting as *open*, so
    the inventory reports what a host exposes now rather than everything it
    has ever exposed. An already-resolved finding is left alone, so an
    analyst's own resolution is not restamped.
    """
    db.execute(
        "UPDATE scan_findings f JOIN hosts h ON h.id = f.host_id "
        "SET f.resolved_at = %s "
        "WHERE f.resolved_at IS NULL AND f.scan_id < ("
        "  SELECT MAX(s.id) FROM scans s JOIN scan_hosts sh ON sh.scan_id = s.id"
        "  WHERE sh.host_id = h.id AND s.status = 'COMPLETED'"
        "  AND COALESCE(s.hosts_up, 0) >= 1)",
        (to_db(utcnow()),),
    )


def _apply_identity_provenance(db: DatabaseManager) -> None:
    """Keep the account of *how* a hostname and OS were established.

    The identity probe already worked this out - which lookup produced the
    name (Nmap's own reverse DNS, the local resolver, mDNS, a NetBIOS or SMB
    query), what named the operating system, and what was tried and came back
    empty. None of it was stored: ``scan_hosts`` had no column for any of the
    three, so the values were computed, used once and dropped.

    The consequence was visible in the interface. The scan-host detail has
    rows for "Hostname source" and "OS source" and a block for the identity
    notes; against a stored scan they could only ever render a dash, and the
    notes never appeared. An operator looking at "Unknown" could not find out
    whether anything had been asked, what had been asked, or why it failed -
    which is the question that actually matters when a whole column reads
    Unknown.

    Existing rows keep the empty default. The provenance for a scan that has
    already run cannot be reconstructed, and guessing which lookup had
    produced a name would be inventing exactly the kind of evidence these
    columns exist to record.
    """
    for column, ddl in (
        ("hostname_source", "VARCHAR(64) NOT NULL DEFAULT '' AFTER os_family"),
        ("os_source", "VARCHAR(64) NOT NULL DEFAULT '' AFTER hostname_source"),
        ("identity_notes", "TEXT NULL AFTER os_source"),
    ):
        if not _column_exists(db, "scan_hosts", column):
            db.execute(f"ALTER TABLE scan_hosts ADD COLUMN {column} {ddl}")


def _apply_host_hostname_source(db: DatabaseManager) -> None:
    """Record where a host's name came from.

    The inventory stored a hostname with no account of how it was obtained.
    That mattered once names could arrive from more than one place: a reverse
    DNS record, a NetBIOS reply, or - new here - a device's own mDNS
    announcement. Those are not equally strong, and an operator looking at a
    name is entitled to know which it is.

    Existing rows keep the empty default. How a name already in the table was
    obtained cannot be recovered, and filling it in would be inventing exactly
    the provenance this column exists to carry.
    """
    if not _column_exists(db, "hosts", "hostname_source"):
        db.execute(
            "ALTER TABLE hosts ADD COLUMN hostname_source VARCHAR(64) "
            "NOT NULL DEFAULT '' AFTER hostname_checked_at"
        )


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "initial_schema", _apply_initial_schema),
    Migration(2, "password_recovery_requests", _apply_password_recovery),
    Migration(3, "incident_read_state", _apply_incident_read_state),
    Migration(4, "hostname_lookup_state", _apply_hostname_lookup_state),
    Migration(5, "os_detail_columns", _apply_os_detail_columns),
    Migration(6, "anomaly_detected_at", _apply_anomaly_detected_at),
    Migration(7, "anomaly_review_marker", _apply_anomaly_review_marker),
    Migration(8, "manuscript_scope_alignment", _apply_scope_alignment),
    Migration(9, "assessment_queue", _apply_assessment_queue),
    Migration(10, "offlink_mac_correction", _apply_offlink_mac_correction),
    Migration(11, "group_mac_correction", _apply_group_mac_correction),
    Migration(12, "per_user_notification_reads", _apply_per_user_notification_reads),
    Migration(13, "enable_auto_assessment", _apply_enable_auto_assessment),
    Migration(14, "manuscript_alignment_rev9", _apply_manuscript_alignment_rev9),
    Migration(15, "manuscript_flood_thresholds", _apply_manuscript_flood_thresholds),
    Migration(16, "traffic_topsource_index", _apply_traffic_topsource_index),
    Migration(17, "host_provenance", _apply_host_provenance),
    Migration(
        18, "no_response_assessment_state", _apply_no_response_assessment_state
    ),
    Migration(19, "supersede_stale_findings", _apply_supersede_stale_findings),
    Migration(20, "identity_provenance", _apply_identity_provenance),
    Migration(21, "host_hostname_source", _apply_host_hostname_source),
)

LATEST_VERSION: int = max(m.version for m in MIGRATIONS)


def _validate_identifier(name: str) -> str:
    """Guard the one place a name must be interpolated (``CREATE DATABASE``).

    MySQL does not accept a bound parameter for a schema name, so the value is
    validated character-by-character instead of being quoted.

    Raises:
        SchemaError: when the name contains anything but ``[A-Za-z0-9_]``.
    """
    candidate = (name or "").strip()
    if not candidate or len(candidate) > 64:
        raise SchemaError(f"Invalid database name: '{name}'")
    if not set(candidate) <= _IDENTIFIER_SAFE:
        raise SchemaError(
            f"Invalid database name '{name}': only letters, digits and "
            "underscores are permitted."
        )
    return candidate


def ensure_database_exists(settings: DatabaseSettings) -> bool:
    """Create the configured schema if the account is permitted to.

    Returns:
        True when the schema exists after the call.

    Raises:
        SchemaError: when the driver is missing or the schema cannot be created
            (for example because the least-privilege account lacks CREATE).
    """
    if not MYSQL_AVAILABLE:
        raise SchemaError(
            f"mysql-connector-python is not installed ({MYSQL_IMPORT_ERROR}).",
            user_message=(
                "The MySQL driver is not installed. Run "
                "'pip install -r requirements.txt'."
            ),
        )

    import mysql.connector
    from mysql.connector import Error as MySQLError

    database = _validate_identifier(settings.database)
    try:
        connection = mysql.connector.connect(
            host=settings.host,
            port=settings.port,
            user=settings.user,
            password=settings.password,
            connection_timeout=settings.connect_timeout,
        )
    except MySQLError as exc:
        raise SchemaError(
            f"Could not connect to MySQL at {settings.host}:{settings.port}: {exc}",
            user_message=(
                "DATABASE OFFLINE - could not connect to the MySQL server. "
                "Check the service and the credentials in the configuration file."
            ),
        ) from exc

    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            connection.commit()
            return True
        except MySQLError as exc:
            raise SchemaError(
                f"Could not create database '{database}': {exc}",
                user_message=(
                    f"The database '{database}' does not exist and could not "
                    "be created with the configured account. Create it "
                    "manually or grant CREATE to the account."
                ),
            ) from exc
        finally:
            cursor.close()
    finally:
        connection.close()


def applied_versions(db: DatabaseManager) -> set[int]:
    """Versions already recorded in ``schema_migrations`` (empty when absent)."""
    try:
        rows = db.query("SELECT version FROM schema_migrations")
    except Exception:  # noqa: BLE001 - table may not exist yet
        return set()
    return {int(row["version"]) for row in rows}


def current_version(db: DatabaseManager) -> int:
    """Highest applied migration version, or ``0`` on a fresh database."""
    versions = applied_versions(db)
    return max(versions) if versions else 0


def run_migrations(db: DatabaseManager) -> list[int]:
    """Apply every migration that has not been applied yet.

    Returns:
        The versions applied during this call (empty when already current).

    Raises:
        SchemaError: when a migration fails; the failure text names the
            migration so an administrator can act on it.
    """
    from aethra_sec.database.schema import SCHEMA_MIGRATIONS

    db.execute(SCHEMA_MIGRATIONS)
    already = applied_versions(db)
    applied: list[int] = []

    for migration in sorted(MIGRATIONS, key=lambda m: m.version):
        if migration.version in already:
            continue
        LOGGER.info("Applying migration %s: %s", migration.version, migration.name)
        try:
            migration.apply(db)
        except Exception as exc:  # noqa: BLE001
            raise SchemaError(
                f"Migration {migration.version} ({migration.name}) failed: {exc}",
                user_message=(
                    f"Database migration {migration.version} failed. The "
                    "schema may be incomplete - see the System Health screen."
                ),
            ) from exc
        db.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (%s, %s, %s)",
            (migration.version, migration.name, to_db(utcnow())),
        )
        applied.append(migration.version)

    if applied:
        LOGGER.info("Applied migrations: %s", applied)
    return applied


def missing_tables(db: DatabaseManager) -> tuple[str, ...]:
    """Required tables that are absent from the schema."""
    present = db.table_names()
    present_lower = {name.lower() for name in present}
    return tuple(t for t in REQUIRED_TABLES if t.lower() not in present_lower)


def verify_schema(db: DatabaseManager) -> tuple[bool, str]:
    """Check that the schema is complete and current.

    Returns:
        ``(ok, detail)``. ``detail`` names the problem when ``ok`` is false, so
        the diagnostics screen can show something actionable.
    """
    missing = missing_tables(db)
    if missing:
        return False, f"Missing tables: {', '.join(missing)}"
    version = current_version(db)
    if version < LATEST_VERSION:
        return (
            False,
            f"Schema version {version} is older than the required "
            f"version {LATEST_VERSION}. Run the migrations.",
        )
    return True, f"Schema version {version} (current)"


def initialise_database(settings: DatabaseSettings) -> DatabaseManager:
    """Create the schema, run migrations, and return a ready manager.

    Used by ``scripts/init_db.py`` and the application's first-run path.
    """
    ensure_database_exists(settings)
    db = DatabaseManager(settings)
    run_migrations(db)
    return db
