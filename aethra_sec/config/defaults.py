"""Built-in default values for tunable AETHRA-SEC behaviour.

These constants are the *fallback* layer only. At runtime the effective value
for every key below is read from the ``system_settings`` table (administrator
editable, see the Settings screen); the database is seeded from this module the
first time the schema is created.

Nothing here is security data - these are thresholds, intervals and limits.
"""

from __future__ import annotations

from typing import Any, NamedTuple


class SettingSpec(NamedTuple):
    """Declarative description of one administrator-tunable setting."""

    key: str
    default: Any
    value_type: str  # "int" | "float" | "bool" | "str"
    category: str
    description: str
    minimum: float | None = None
    maximum: float | None = None


# --------------------------------------------------------------------------
# Detection thresholds (§91 - configurable, never hard-coded at the call site)
# --------------------------------------------------------------------------
DETECTION_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "detection.icmp_packets_per_second",
        120,
        "int",
        "detection",
        "ICMP packets per second from a single source that constitutes an "
        "ICMP flood. Default 120 pps is the manuscript's section 3.9.8 threshold.",
        minimum=1,
        maximum=1_000_000,
    ),
    SettingSpec(
        "detection.udp_packets_per_second",
        300,
        "int",
        "detection",
        "UDP packets per second from a single source toward one destination "
        "that constitutes a UDP flood. Default 300 pps is the manuscript's "
        "section 3.9.8 threshold.",
        minimum=1,
        maximum=1_000_000,
    ),
    SettingSpec(
        "detection.tcp_syn_per_second",
        200,
        "int",
        "detection",
        "TCP SYN packets per second from a single source that constitutes a "
        "SYN flood. Default 200 pps is the manuscript's section 3.9.8 threshold.",
        minimum=1,
        maximum=1_000_000,
    ),
    SettingSpec(
        "detection.tcp_syn_unanswered_ratio",
        0.8,
        "float",
        "detection",
        "Minimum proportion of SYN packets without an observed SYN/ACK reply "
        "before a SYN flood indicator is raised.",
        minimum=0.0,
        maximum=1.0,
    ),
    SettingSpec(
        "detection.http_requests_per_second",
        10,
        "int",
        "detection",
        "HTTP requests per second from a single source that constitutes an "
        "HTTP flood. Default 10 per second is the manuscript's section 3.9.8 "
        "threshold of 600 requests per minute.",
        minimum=1,
        maximum=1_000_000,
    ),
    SettingSpec(
        "detection.port_scan_distinct_ports",
        20,
        "int",
        "detection",
        "Distinct destination ports contacted by one source inside the port "
        "scan window before port-scanning behaviour is reported.",
        minimum=2,
        maximum=65_535,
    ),
    SettingSpec(
        "detection.port_scan_window_seconds",
        10,
        "int",
        "detection",
        "Sliding window, in seconds, used by the port-scan rule.",
        minimum=1,
        maximum=3600,
    ),
    SettingSpec(
        "detection.host_sweep_distinct_hosts",
        15,
        "int",
        "detection",
        "Distinct destination hosts contacted by one source inside the sweep "
        "window before host-sweep behaviour is reported.",
        minimum=2,
        maximum=65_535,
    ),
    SettingSpec(
        "detection.host_sweep_range_concentration",
        0.75,
        "float",
        "detection",
        "Share of the contacted addresses that must fall inside one /24 "
        "before host-sweep behaviour is reported. A sweep walks an address "
        "range; ordinary outbound traffic reaches scattered addresses that "
        "share no prefix, so counting distinct destinations alone reported "
        "normal browsing as a sweep.",
        minimum=0.0,
        maximum=1.0,
    ),
    SettingSpec(
        "detection.host_sweep_window_seconds",
        10,
        "int",
        "detection",
        "Sliding window, in seconds, used by the host-sweep rule.",
        minimum=1,
        maximum=3600,
    ),
    SettingSpec(
        "detection.rate_window_seconds",
        5,
        "int",
        "detection",
        "Sliding window, in seconds, used by the packet-rate flood rules.",
        minimum=1,
        maximum=600,
    ),
    SettingSpec(
        "detection.suppression_window_seconds",
        120,
        "int",
        "detection",
        "Minimum interval between two identical traffic anomalies for the "
        "same source before a new record is written (false-positive control).",
        minimum=1,
        maximum=86_400,
    ),
    SettingSpec(
        "detection.enabled",
        True,
        "bool",
        "detection",
        "Master switch for deterministic traffic-analysis rules. Snort alert "
        "ingest is unaffected by this setting.",
    ),
)

# --------------------------------------------------------------------------
# Correlation (§26, §92)
# --------------------------------------------------------------------------
CORRELATION_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "correlation.window_seconds",
        300,
        "int",
        "correlation",
        "Events sharing a correlation key inside this window are attached to "
        "the same incident instead of creating a new one.",
        minimum=10,
        maximum=86_400,
    ),
    SettingSpec(
        "correlation.reopen_resolved",
        False,
        "bool",
        "correlation",
        "When enabled, new evidence re-opens a RESOLVED incident instead of "
        "creating a follow-up incident.",
    ),
    SettingSpec(
        "correlation.enabled",
        True,
        "bool",
        "correlation",
        "Master switch for the threat correlation engine.",
    ),
    SettingSpec(
        "correlation.min_events_for_incident",
        1,
        "int",
        "correlation",
        "Number of correlated evidence events required before an incident is "
        "created. 1 means every qualifying security event yields an incident.",
        minimum=1,
        maximum=1000,
    ),
)

# --------------------------------------------------------------------------
# Capture / persistence (§36, §79, §106)
# --------------------------------------------------------------------------
CAPTURE_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "capture.queue_size",
        20_000,
        "int",
        "capture",
        "Maximum number of decoded packets buffered between the capture "
        "reader and the processing worker. Excess packets are dropped and "
        "counted rather than growing memory without bound.",
        minimum=100,
        maximum=1_000_000,
    ),
    SettingSpec(
        "capture.pcap_ring_mb",
        64,
        "int",
        "capture",
        "Size of each capture file in the evidence ring, in megabytes. The "
        "session's packets are written to a series of files of this size and "
        "TShark deletes the oldest, so a long capture cannot fill the disk. "
        "Total on disk is this multiplied by the file count. Set either to 0 "
        "for a single file that grows without limit.",
        minimum=0,
        maximum=4_096,
    ),
    SettingSpec(
        "capture.pcap_ring_files",
        8,
        "int",
        "capture",
        "How many capture files the evidence ring keeps. Once full, the "
        "oldest is deleted as a new one begins. A packet whose file has been "
        "recycled can no longer be inspected in detail, and the inspector "
        "says so rather than showing something else.",
        minimum=0,
        maximum=1_000,
    ),
    SettingSpec(
        "capture.persist_packet_metadata",
        True,
        "bool",
        "capture",
        "Persist per-packet metadata to traffic_records. Aggregates are stored "
        "regardless of this setting.",
    ),
    SettingSpec(
        "capture.persist_batch_size",
        200,
        "int",
        "capture",
        "Number of packet metadata rows written per batched INSERT.",
        minimum=1,
        maximum=10_000,
    ),
    SettingSpec(
        "capture.persist_flush_seconds",
        2,
        "int",
        "capture",
        "Maximum age of a partially filled packet batch before it is flushed.",
        minimum=1,
        maximum=300,
    ),
    SettingSpec(
        "capture.max_packet_rows_per_minute",
        6_000,
        "int",
        "capture",
        "Upper bound on packet metadata rows written per minute. Beyond this "
        "rate packets are still analysed and aggregated, but only sampled for "
        "row-level storage; the sampling ratio is reported in the UI.",
        minimum=0,
        maximum=1_000_000,
    ),
    SettingSpec(
        "capture.aggregate_interval_seconds",
        10,
        "int",
        "capture",
        "Interval at which traffic aggregates are computed and persisted.",
        minimum=1,
        maximum=3600,
    ),
    SettingSpec(
        "capture.decode_workers",
        1,
        "int",
        "capture",
        "Number of packet-processing worker threads.",
        minimum=1,
        maximum=8,
    ),
)

# --------------------------------------------------------------------------
# Retention (§79)
# --------------------------------------------------------------------------
RETENTION_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "retention.traffic_records_hours",
        24,
        "int",
        "retention",
        "Hours of per-packet metadata kept before pruning. 0 disables pruning "
        "(not recommended on a live network).",
        minimum=0,
        maximum=8760,
    ),
    SettingSpec(
        "retention.traffic_aggregates_days",
        30,
        "int",
        "retention",
        "Days of traffic aggregates kept before pruning.",
        minimum=0,
        maximum=3650,
    ),
    SettingSpec(
        "retention.snort_alerts_days",
        90,
        "int",
        "retention",
        "Days of Snort alerts kept before pruning.",
        minimum=0,
        maximum=3650,
    ),
    SettingSpec(
        "retention.audit_logs_days",
        365,
        "int",
        "retention",
        "Days of audit records kept. Audit pruning is administrator-triggered "
        "only and is itself audited.",
        minimum=0,
        maximum=3650,
    ),
    SettingSpec(
        "retention.scan_history_days",
        365,
        "int",
        "retention",
        "Days of Nmap scan history kept before pruning.",
        minimum=0,
        maximum=3650,
    ),
    SettingSpec(
        "retention.prune_interval_minutes",
        60,
        "int",
        "retention",
        "How often the retention job runs.",
        minimum=1,
        maximum=10_080,
    ),
)

# --------------------------------------------------------------------------
# Host inventory
#
# Reverse DNS is off by default. Resolving every address seen on the wire
# sends a query to a nameserver for each one, which is traffic an operator
# monitoring a network should be choosing to generate, not discovering.
# --------------------------------------------------------------------------
HOST_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "hosts.auto_resolve_hostnames",
        False,
        "bool",
        "hosts",
        "Look up hostnames for newly observed addresses in the background. "
        "Each lookup is one reverse DNS query; addresses with no record are "
        "asked once and then left alone.",
    ),
    SettingSpec(
        "hosts.resolve_interval_minutes",
        5,
        "int",
        "hosts",
        "How often the background hostname resolver runs.",
        minimum=1,
        maximum=1440,
    ),
    SettingSpec(
        "hosts.offline_after_minutes",
        15,
        "int",
        "hosts",
        "A host not observed for this many minutes is marked OFFLINE. Its "
        "history, its assessments and its findings are kept; it returns to UP "
        "the moment it is observed transmitting again.",
        minimum=1,
        maximum=10080,
    ),
)

# --------------------------------------------------------------------------
# Database backup (§111)
#
# The automatic schedule is off by default. A job that writes a full copy of
# the database to disk on its own is opt-in, not something an installation
# should start doing because nobody looked at the settings.
# --------------------------------------------------------------------------
BACKUP_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "backup.automatic_enabled",
        False,
        "bool",
        "backup",
        "Run a database backup automatically once the interval below has "
        "elapsed since the newest existing backup.",
    ),
    SettingSpec(
        "backup.interval_hours",
        24,
        "int",
        "backup",
        "Hours between automatic backups. The countdown is measured from the "
        "newest backup already on disk, so restarting does not reset it.",
        minimum=1,
        maximum=8760,
    ),
    SettingSpec(
        "backup.directory",
        "",
        "str",
        "backup",
        "Where backups are written. Leave empty to use the 'backups' folder "
        "beside the report output directory.",
    ),
    SettingSpec(
        "backup.keep_files",
        7,
        "int",
        "backup",
        "How many backup files to keep. The oldest beyond this count are "
        "deleted after a successful backup; 0 keeps every file forever.",
        minimum=0,
        maximum=1000,
    ),
)

# --------------------------------------------------------------------------
# Interface / presentation
# --------------------------------------------------------------------------
UI_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "ui.refresh_interval_ms",
        2000,
        "int",
        "ui",
        "Dashboard refresh cadence in milliseconds.",
        minimum=250,
        maximum=60_000,
    ),
    SettingSpec(
        "ui.packet_table_max_rows",
        2000,
        "int",
        "ui",
        "Maximum rows retained in the live packet table before the oldest are "
        "removed from the view (the database retains its own history).",
        minimum=100,
        maximum=100_000,
    ),
    SettingSpec(
        "ui.chart_points",
        60,
        "int",
        "ui",
        "Number of downsampled points drawn in time-series charts.",
        minimum=10,
        maximum=1000,
    ),
)

# --------------------------------------------------------------------------
# Security / session
# --------------------------------------------------------------------------
SECURITY_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "security.max_failed_logins",
        5,
        "int",
        "security",
        "Consecutive failed logins before an account is locked.",
        minimum=1,
        maximum=100,
    ),
    SettingSpec(
        "security.lockout_minutes",
        15,
        "int",
        "security",
        "Duration of an automatic account lockout, in minutes.",
        minimum=1,
        maximum=10_080,
    ),
    SettingSpec(
        "security.session_timeout_minutes",
        60,
        "int",
        "security",
        "Idle time after which a session is invalidated.",
        minimum=1,
        maximum=10_080,
    ),
    SettingSpec(
        "security.password_min_length",
        12,
        "int",
        "security",
        "Minimum accepted password length.",
        minimum=8,
        maximum=128,
    ),
    SettingSpec(
        "security.reset_request_ttl_hours",
        24,
        "int",
        "security",
        "How long a password-reset request waits for an administrator before "
        "it expires, in hours.",
        minimum=1,
        maximum=720,
    ),
    SettingSpec(
        "security.reset_code_ttl_minutes",
        60,
        "int",
        "security",
        "How long an approved recovery code stays usable, in minutes.",
        minimum=5,
        maximum=1440,
    ),
    SettingSpec(
        "security.reset_max_code_attempts",
        5,
        "int",
        "security",
        "Wrong recovery codes accepted before an approval is revoked.",
        minimum=1,
        maximum=20,
    ),
    SettingSpec(
        "security.audit_hash_chain",
        True,
        "bool",
        "security",
        "Maintain chained SHA-256 integrity hashes over audit records.",
    ),
)

# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
NOTIFICATION_SETTINGS: tuple[SettingSpec, ...] = (
    SettingSpec(
        "notifications.enabled",
        True,
        "bool",
        "notifications",
        "Raise in-application notifications for genuine system events.",
    ),
    SettingSpec(
        "notifications.min_severity",
        "MEDIUM",
        "str",
        "notifications",
        "Lowest security severity that raises a notification "
        "(INFO/LOW/MEDIUM/HIGH/CRITICAL).",
    ),
    SettingSpec(
        "assessment.auto_enabled",
        True,
        "bool",
        "assessment",
        "Automatically assess hosts observed on the monitored authorised "
        "network. When on, a host the capture pipeline observes on the "
        "subnet of the monitored interface, inside AETHRA_AUTHORIZED_NETWORKS, "
        "is assessed with real Nmap once and then only after the reassessment "
        "interval. When that network cannot be determined, automatic "
        "assessment stops and says so. It can be switched off from the "
        "Vulnerability Assessment screen.",
    ),
    SettingSpec(
        "assessment.retry_base_minutes",
        5,
        "int",
        "assessment",
        "Minutes before a failed or timed-out assessment is retried. The delay "
        "doubles with each consecutive failure and never exceeds the "
        "reassessment interval.",
        minimum=1,
        maximum=1440,
    ),
    SettingSpec(
        "assessment.scan_timeout_seconds",
        1800,
        "int",
        "assessment",
        "Wall-clock limit for one Nmap run. When it passes, Nmap is stopped "
        "and the assessment is recorded as TIMEOUT - never as completed.",
        minimum=30,
        maximum=86_400,
    ),
    SettingSpec(
        "assessment.max_scope_addresses",
        1024,
        "int",
        "assessment",
        "Largest monitored network, in addresses, automatic assessment will "
        "accept. A larger network is not a laboratory segment, so automatic "
        "assessment reports its scope as unavailable instead of scanning it.",
        minimum=4,
        maximum=65_536,
    ),
    SettingSpec(
        "assessment.auto_new_hosts",
        True,
        "bool",
        "assessment",
        "Assess a newly discovered host the first time it is seen, rather "
        "than waiting for the reassessment interval.",
    ),
    SettingSpec(
        "assessment.reassess_hours",
        6,
        "int",
        "assessment",
        "Hours before an already-assessed host is due again. A host is not "
        "rescanned inside this window however much traffic it sends.",
        minimum=1,
        maximum=8760,
    ),
    SettingSpec(
        "assessment.max_concurrent",
        2,
        "int",
        "assessment",
        "Nmap assessments that may run at once. A burst of newly discovered "
        "hosts becomes a queue rather than a process per host.",
        minimum=1,
        maximum=8,
    ),
    SettingSpec(
        "assessment.max_attempts",
        3,
        "int",
        "assessment",
        "Consecutive failed or timed-out assessments before a host is retried "
        "only at the reassessment interval. Prevents a permanently "
        "unreachable address being scanned every few minutes.",
        minimum=1,
        maximum=20,
    ),
    SettingSpec(
        "assessment.auto_profile",
        "standard",
        "str",
        "assessment",
        "Nmap profile used for automatic assessment, from the fixed profile "
        "catalogue. Automatic scans cannot use arbitrary Nmap arguments.",
    ),
    SettingSpec(
        "assessment.script_categories",
        "vuln",
        "str",
        "assessment",
        "Nmap NSE script categories run during automatic assessment, comma "
        "separated. Only assessment categories are accepted (default, safe, "
        "banner, vuln); exploit, brute, dos, intrusive, malware and auth are "
        "refused. 'vuln' is what supplies the CVE evidence a host needs before "
        "it can be classified Vulnerable - without it an assessment can only "
        "record which ports are open, which is exposure and not vulnerability. "
        "Leave empty to run no scripts, which makes scans faster and quieter.",
    ),
    SettingSpec(
        "assessment.excluded_addresses",
        "",
        "str",
        "assessment",
        "Comma-separated addresses never assessed automatically, whatever "
        "else the policy says. For equipment that must not be scanned.",
    ),
    SettingSpec(
        "incidents.auto_close_hours",
        24,
        "int",
        "correlation",
        "Close an untouched incident once its evidence has been quiet for "
        "this many hours. Correlation refreshes an incident whenever new "
        "evidence arrives, so anything still happening stays open; this only "
        "retires the tail nobody will action. Nothing is deleted - the "
        "incident keeps its evidence and stays searchable. Set to 0 to keep "
        "every incident open until a person closes it.",
        minimum=0,
        maximum=8760,
    ),
    SettingSpec(
        "notifications.sound_enabled",
        True,
        "bool",
        "notifications",
        "Play a sound when a notification is raised from a real event.",
    ),
    SettingSpec(
        "notifications.sound_min_level",
        "WARNING",
        "str",
        "notifications",
        "Lowest notification level that is audible "
        "(INFO/SUCCESS/WARNING/ERROR/CRITICAL). Levels below this stay "
        "visual only.",
    ),
    SettingSpec(
        "notifications.repeat_critical",
        True,
        "bool",
        "notifications",
        "Re-sound an unacknowledged CRITICAL notification every 20 seconds "
        "until it is acknowledged.",
    ),
    SettingSpec(
        "notifications.quiet_mode",
        False,
        "bool",
        "notifications",
        "Do not disturb: keep notifications visual, suppressing all sound.",
    ),
    SettingSpec(
        "notifications.sound_dedup_seconds",
        30,
        "int",
        "notifications",
        "Seconds within which repeats of the same finding fold into the "
        "first sound. The notification record still counts every occurrence.",
    ),
    SettingSpec(
        "notifications.max_retained",
        500,
        "int",
        "notifications",
        "Maximum notifications retained per user.",
        minimum=10,
        maximum=100_000,
    ),
)

ALL_SETTING_SPECS: tuple[SettingSpec, ...] = (
    DETECTION_SETTINGS
    + CORRELATION_SETTINGS
    + CAPTURE_SETTINGS
    + RETENTION_SETTINGS
    + HOST_SETTINGS
    + BACKUP_SETTINGS
    + UI_SETTINGS
    + SECURITY_SETTINGS
    + NOTIFICATION_SETTINGS
)

SETTING_SPEC_BY_KEY: dict[str, SettingSpec] = {s.key: s for s in ALL_SETTING_SPECS}


def default_for(key: str) -> Any:
    """Return the built-in default for ``key``.

    Raises:
        KeyError: if ``key`` is not a declared setting.
    """
    return SETTING_SPEC_BY_KEY[key].default
