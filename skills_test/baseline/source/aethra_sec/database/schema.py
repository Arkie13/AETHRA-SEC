"""MySQL schema definition for AETHRA-SEC.

Design notes:

* All timestamps are ``DATETIME(6)`` holding **UTC**; conversion to local time
  happens only at display (§80).
* Structured payloads (evidence maps, metadata) are stored as ``TEXT``
  containing JSON rather than the ``JSON`` column type, so the schema works
  identically on MySQL 5.7/8.x and MariaDB 10.x.
* Evidence tables (``snort_alerts``, ``scan_findings``, ``traffic_anomalies``,
  ``audit_logs``) use ``ON DELETE RESTRICT`` / ``SET NULL`` for their parents:
  security evidence is never silently cascaded away (§110).
* Every column the interface filters or sorts on carries an index (§114).

The tables are created in dependency order; ``CREATE_TABLE_STATEMENTS`` is the
authoritative order used by the migration runner.
"""

from __future__ import annotations

TABLE_OPTIONS = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

SCHEMA_MIGRATIONS = f"""
CREATE TABLE IF NOT EXISTS schema_migrations (
    version         INT UNSIGNED NOT NULL,
    name            VARCHAR(128) NOT NULL,
    applied_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (version)
) {TABLE_OPTIONS}
"""

ROLES = f"""
CREATE TABLE IF NOT EXISTS roles (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name            VARCHAR(32)  NOT NULL,
    description     VARCHAR(255) NOT NULL DEFAULT '',
    created_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name)
) {TABLE_OPTIONS}
"""

PERMISSIONS = f"""
CREATE TABLE IF NOT EXISTS permissions (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    code            VARCHAR(64)  NOT NULL,
    name            VARCHAR(128) NOT NULL,
    description     VARCHAR(255) NOT NULL DEFAULT '',
    category        VARCHAR(32)  NOT NULL DEFAULT 'general',
    PRIMARY KEY (id),
    UNIQUE KEY uq_permissions_code (code),
    KEY ix_permissions_category (category)
) {TABLE_OPTIONS}
"""

ROLE_PERMISSIONS = f"""
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id         INT UNSIGNED NOT NULL,
    permission_id   INT UNSIGNED NOT NULL,
    granted_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    KEY ix_role_permissions_permission (permission_id),
    CONSTRAINT fk_role_permissions_role
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

USERS = f"""
CREATE TABLE IF NOT EXISTS users (
    id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username            VARCHAR(32)  NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    password_algorithm  VARCHAR(32)  NOT NULL DEFAULT 'argon2id',
    full_name           VARCHAR(128) NOT NULL DEFAULT '',
    email               VARCHAR(190) NOT NULL DEFAULT '',
    role_id             INT UNSIGNED NULL,
    is_active           TINYINT(1)   NOT NULL DEFAULT 1,
    is_locked           TINYINT(1)   NOT NULL DEFAULT 0,
    failed_login_count  INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until        DATETIME(6)  NULL,
    last_login_at       DATETIME(6)  NULL,
    last_login_host     VARCHAR(128) NOT NULL DEFAULT '',
    password_changed_at DATETIME(6)  NULL,
    must_change_password TINYINT(1)  NOT NULL DEFAULT 0,
    created_at          DATETIME(6)  NOT NULL,
    updated_at          DATETIME(6)  NOT NULL,
    created_by          INT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    KEY ix_users_role (role_id),
    KEY ix_users_active (is_active),
    CONSTRAINT fk_users_role
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_users_created_by
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

LOGIN_ATTEMPTS = f"""
CREATE TABLE IF NOT EXISTS login_attempts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username        VARCHAR(64)  NOT NULL,
    user_id         INT UNSIGNED NULL,
    successful      TINYINT(1)   NOT NULL DEFAULT 0,
    reason          VARCHAR(128) NOT NULL DEFAULT '',
    host_context    VARCHAR(128) NOT NULL DEFAULT '',
    attempted_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_login_attempts_username_time (username, attempted_at),
    KEY ix_login_attempts_time (attempted_at),
    KEY ix_login_attempts_user (user_id),
    CONSTRAINT fk_login_attempts_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

SESSIONS = f"""
CREATE TABLE IF NOT EXISTS sessions (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id             INT UNSIGNED NOT NULL,
    token_fingerprint   CHAR(64)     NOT NULL,
    host_context        VARCHAR(128) NOT NULL DEFAULT '',
    created_at          DATETIME(6)  NOT NULL,
    last_activity_at    DATETIME(6)  NOT NULL,
    expires_at          DATETIME(6)  NULL,
    ended_at            DATETIME(6)  NULL,
    end_reason          VARCHAR(64)  NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_fingerprint (token_fingerprint),
    KEY ix_sessions_user (user_id),
    KEY ix_sessions_active (ended_at, expires_at),
    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

#: Password recovery queue (§6, §70). A request never changes a credential by
#: itself: it waits for an administrator, and the authorisation code issued on
#: approval is stored only as a SHA-256 digest, exactly like a session token.
PASSWORD_RESET_REQUESTS = f"""
CREATE TABLE IF NOT EXISTS password_reset_requests (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id             INT UNSIGNED NOT NULL,
    username            VARCHAR(32)  NOT NULL,
    status              VARCHAR(16)  NOT NULL DEFAULT 'PENDING',
    reason              VARCHAR(255) NOT NULL DEFAULT '',
    contact             VARCHAR(190) NOT NULL DEFAULT '',
    host_context        VARCHAR(128) NOT NULL DEFAULT '',
    requested_at        DATETIME(6)  NOT NULL,
    expires_at          DATETIME(6)  NOT NULL,
    reviewed_by         INT UNSIGNED NULL,
    reviewed_at         DATETIME(6)  NULL,
    review_note         VARCHAR(255) NOT NULL DEFAULT '',
    code_hash           CHAR(64)     NULL,
    code_expires_at     DATETIME(6)  NULL,
    code_attempts       INT UNSIGNED NOT NULL DEFAULT 0,
    completed_at        DATETIME(6)  NULL,
    PRIMARY KEY (id),
    KEY ix_password_resets_user (user_id),
    KEY ix_password_resets_status (status, requested_at),
    KEY ix_password_resets_username (username, status),
    CONSTRAINT fk_password_resets_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_password_resets_reviewer
        FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

AUDIT_LOGS = f"""
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at     DATETIME(6)  NOT NULL,
    user_id         INT UNSIGNED NULL,
    username        VARCHAR(64)  NOT NULL DEFAULT '',
    action          VARCHAR(64)  NOT NULL,
    category        VARCHAR(32)  NOT NULL DEFAULT 'general',
    target_type     VARCHAR(48)  NOT NULL DEFAULT '',
    target_id       VARCHAR(64)  NOT NULL DEFAULT '',
    result          VARCHAR(16)  NOT NULL DEFAULT 'SUCCESS',
    detail          TEXT         NULL,
    host_context    VARCHAR(128) NOT NULL DEFAULT '',
    source          VARCHAR(24)  NOT NULL DEFAULT 'SYSTEM',
    previous_hash   CHAR(64)     NOT NULL DEFAULT '',
    record_hash     CHAR(64)     NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_audit_time (occurred_at),
    KEY ix_audit_user (user_id),
    KEY ix_audit_action (action),
    KEY ix_audit_category (category),
    KEY ix_audit_target (target_type, target_id),
    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

HOSTS = f"""
CREATE TABLE IF NOT EXISTS hosts (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address          VARCHAR(45)  NOT NULL,
    mac_address         VARCHAR(17)  NOT NULL DEFAULT '',
    hostname            VARCHAR(190) NOT NULL DEFAULT '',
    hostname_checked_at DATETIME(6)  NULL,
    hostname_source     VARCHAR(64)  NOT NULL DEFAULT '',
    vendor              VARCHAR(128) NOT NULL DEFAULT '',
    os_name             VARCHAR(190) NOT NULL DEFAULT '',
    os_version          VARCHAR(96)  NOT NULL DEFAULT '',
    os_cpe              VARCHAR(190) NOT NULL DEFAULT '',
    os_accuracy         TINYINT UNSIGNED NULL,
    status              VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN',
    risk_level          VARCHAR(16)  NOT NULL DEFAULT 'INFORMATIONAL',
    discovery_source    VARCHAR(16)  NOT NULL DEFAULT 'LEGACY',
    discovery_interface VARCHAR(190) NOT NULL DEFAULT '',
    discovery_detail    VARCHAR(190) NOT NULL DEFAULT '',
    is_trusted          TINYINT(1)   NOT NULL DEFAULT 0,
    trust_note          VARCHAR(255) NOT NULL DEFAULT '',
    detected_at         DATETIME(6)  NULL,
    reviewed_at         DATETIME(6)  NULL,
    reviewed_by         INT UNSIGNED NULL,
    first_seen          DATETIME(6)  NOT NULL,
    last_seen           DATETIME(6)  NOT NULL,
    created_at          DATETIME(6)  NOT NULL,
    updated_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_hosts_ip (ip_address),
    KEY ix_hosts_last_seen (last_seen),
    KEY ix_hosts_risk (risk_level),
    KEY ix_hosts_status (status),
    KEY ix_hosts_mac (mac_address)
) {TABLE_OPTIONS}
"""

HOST_OBSERVATIONS = f"""
CREATE TABLE IF NOT EXISTS host_observations (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id             BIGINT UNSIGNED NOT NULL,
    interface           VARCHAR(96)  NOT NULL DEFAULT '',
    protocol            VARCHAR(16)  NOT NULL DEFAULT '',
    packets_sent        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    packets_received    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_sent          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_received      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    first_seen          DATETIME(6)  NOT NULL,
    last_seen           DATETIME(6)  NOT NULL,
    source              VARCHAR(16)  NOT NULL DEFAULT 'PYSHARK',
    PRIMARY KEY (id),
    UNIQUE KEY uq_host_observation (host_id, interface, protocol),
    KEY ix_host_observations_last_seen (last_seen),
    CONSTRAINT fk_host_observations_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

TRUSTED_HOSTS = f"""
CREATE TABLE IF NOT EXISTS trusted_hosts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address      VARCHAR(45)  NOT NULL,
    label           VARCHAR(128) NOT NULL DEFAULT '',
    reason          VARCHAR(255) NOT NULL DEFAULT '',
    added_by        INT UNSIGNED NULL,
    created_at      DATETIME(6)  NOT NULL,
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_trusted_hosts_ip (ip_address),
    CONSTRAINT fk_trusted_hosts_user
        FOREIGN KEY (added_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

SCANS = f"""
CREATE TABLE IF NOT EXISTS scans (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    target              VARCHAR(255) NOT NULL,
    target_kind         VARCHAR(16)  NOT NULL DEFAULT '',
    profile             VARCHAR(32)  NOT NULL DEFAULT '',
    profile_label       VARCHAR(96)  NOT NULL DEFAULT '',
    port_spec           VARCHAR(255) NOT NULL DEFAULT '',
    timing              VARCHAR(8)   NOT NULL DEFAULT '',
    arguments           VARCHAR(512) NOT NULL DEFAULT '',
    status              VARCHAR(16)  NOT NULL DEFAULT 'QUEUED',
    started_at          DATETIME(6)  NULL,
    finished_at         DATETIME(6)  NULL,
    duration_seconds    DECIMAL(12,3) NULL,
    hosts_total         INT UNSIGNED NOT NULL DEFAULT 0,
    hosts_up            INT UNSIGNED NOT NULL DEFAULT 0,
    open_ports          INT UNSIGNED NOT NULL DEFAULT 0,
    findings_count      INT UNSIGNED NOT NULL DEFAULT 0,
    error_message       VARCHAR(512) NOT NULL DEFAULT '',
    nmap_version        VARCHAR(64)  NOT NULL DEFAULT '',
    command_line        VARCHAR(512) NOT NULL DEFAULT '',
    initiated_by        INT UNSIGNED NULL,
    created_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_scans_created (created_at),
    KEY ix_scans_status (status),
    KEY ix_scans_target (target),
    KEY ix_scans_user (initiated_by),
    CONSTRAINT fk_scans_user
        FOREIGN KEY (initiated_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

SCAN_HOSTS = f"""
CREATE TABLE IF NOT EXISTS scan_hosts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id         BIGINT UNSIGNED NOT NULL,
    host_id         BIGINT UNSIGNED NULL,
    ip_address      VARCHAR(45)  NOT NULL,
    hostname        VARCHAR(190) NOT NULL DEFAULT '',
    mac_address     VARCHAR(17)  NOT NULL DEFAULT '',
    vendor          VARCHAR(128) NOT NULL DEFAULT '',
    status          VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN',
    os_name         VARCHAR(190) NOT NULL DEFAULT '',
    os_version      VARCHAR(96)  NOT NULL DEFAULT '',
    os_cpe          VARCHAR(190) NOT NULL DEFAULT '',
    os_accuracy     TINYINT UNSIGNED NULL,
    os_family       VARCHAR(96)  NOT NULL DEFAULT '',
    hostname_source VARCHAR(64)  NOT NULL DEFAULT '',
    os_source       VARCHAR(64)  NOT NULL DEFAULT '',
    identity_notes  TEXT         NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_hosts (scan_id, ip_address),
    KEY ix_scan_hosts_host (host_id),
    CONSTRAINT fk_scan_hosts_scan
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_hosts_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

PORTS = f"""
CREATE TABLE IF NOT EXISTS ports (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_host_id    BIGINT UNSIGNED NOT NULL,
    port            SMALLINT UNSIGNED NOT NULL,
    protocol        VARCHAR(8)   NOT NULL DEFAULT 'tcp',
    state           VARCHAR(16)  NOT NULL DEFAULT '',
    service         VARCHAR(64)  NOT NULL DEFAULT '',
    product         VARCHAR(128) NOT NULL DEFAULT '',
    version         VARCHAR(128) NOT NULL DEFAULT '',
    extra_info      VARCHAR(255) NOT NULL DEFAULT '',
    cpe             VARCHAR(255) NOT NULL DEFAULT '',
    reason          VARCHAR(64)  NOT NULL DEFAULT '',
    tunnel          VARCHAR(32)  NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uq_ports (scan_host_id, protocol, port),
    KEY ix_ports_state (state),
    KEY ix_ports_service (service),
    KEY ix_ports_port (port),
    CONSTRAINT fk_ports_scan_host
        FOREIGN KEY (scan_host_id) REFERENCES scan_hosts (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

SCAN_FINDINGS = f"""
CREATE TABLE IF NOT EXISTS scan_findings (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id                 BIGINT UNSIGNED NOT NULL,
    scan_host_id            BIGINT UNSIGNED NULL,
    host_id                 BIGINT UNSIGNED NULL,
    ip_address              VARCHAR(45)  NOT NULL DEFAULT '',
    port                    SMALLINT UNSIGNED NULL,
    protocol                VARCHAR(8)   NOT NULL DEFAULT '',
    service                 VARCHAR(64)  NOT NULL DEFAULT '',
    title                   VARCHAR(190) NOT NULL,
    observation             TEXT         NULL,
    concern                 TEXT         NULL,
    risk_level              VARCHAR(16)  NOT NULL DEFAULT 'INFORMATIONAL',
    risk_rationale          TEXT         NULL,
    evidence                TEXT         NULL,
    reference_id            VARCHAR(64)  NOT NULL DEFAULT '',
    reference_source        VARCHAR(64)  NOT NULL DEFAULT '',
    verification_required   TINYINT(1)   NOT NULL DEFAULT 1,
    source                  VARCHAR(16)  NOT NULL DEFAULT 'NMAP',
    resolved_at             DATETIME(6)  NULL,
    created_at              DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_findings_scan (scan_id),
    KEY ix_findings_host (host_id),
    KEY ix_findings_risk (risk_level),
    KEY ix_findings_created (created_at),
    KEY ix_findings_resolved (resolved_at),
    KEY ix_findings_ip (ip_address),
    CONSTRAINT fk_findings_scan
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    CONSTRAINT fk_findings_scan_host
        FOREIGN KEY (scan_host_id) REFERENCES scan_hosts (id) ON DELETE CASCADE,
    CONSTRAINT fk_findings_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

VULN_KNOWLEDGE = f"""
CREATE TABLE IF NOT EXISTS vuln_knowledge (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    service             VARCHAR(64)  NOT NULL DEFAULT '',
    product_pattern     VARCHAR(190) NOT NULL DEFAULT '',
    version_pattern     VARCHAR(190) NOT NULL DEFAULT '',
    port                SMALLINT UNSIGNED NULL,
    title               VARCHAR(190) NOT NULL,
    concern             TEXT         NULL,
    risk_level          VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    reference_id        VARCHAR(64)  NOT NULL DEFAULT '',
    reference_source    VARCHAR(64)  NOT NULL DEFAULT '',
    is_active           TINYINT(1)   NOT NULL DEFAULT 1,
    created_by          INT UNSIGNED NULL,
    created_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_vuln_knowledge_service (service),
    KEY ix_vuln_knowledge_active (is_active),
    CONSTRAINT fk_vuln_knowledge_user
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

TRAFFIC_RECORDS = f"""
CREATE TABLE IF NOT EXISTS traffic_records (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    captured_at     DATETIME(6)  NOT NULL,
    interface       VARCHAR(96)  NOT NULL DEFAULT '',
    src_ip          VARCHAR(45)  NOT NULL DEFAULT '',
    dst_ip          VARCHAR(45)  NOT NULL DEFAULT '',
    src_port        SMALLINT UNSIGNED NULL,
    dst_port        SMALLINT UNSIGNED NULL,
    protocol        VARCHAR(16)  NOT NULL DEFAULT '',
    app_protocol    VARCHAR(24)  NOT NULL DEFAULT '',
    length          INT UNSIGNED NOT NULL DEFAULT 0,
    ttl             SMALLINT UNSIGNED NULL,
    tcp_flags       SMALLINT UNSIGNED NULL,
    src_mac         VARCHAR(17)  NOT NULL DEFAULT '',
    dst_mac         VARCHAR(17)  NOT NULL DEFAULT '',
    info            VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_traffic_captured (captured_at),
    KEY ix_traffic_src (src_ip, captured_at),
    KEY ix_traffic_dst (dst_ip, captured_at),
    KEY ix_traffic_protocol (protocol),
    KEY ix_traffic_dst_port (dst_port),
    -- Covering index for the dashboard's top-sources panel: grouping the
    -- window's packets by source is served straight from the index, without
    -- reading table rows (measured ~1.9s -> ~0.8s over 100k+ rows).
    KEY ix_traffic_period_src (captured_at, src_ip, length)
) {TABLE_OPTIONS}
"""

TRAFFIC_AGGREGATES = f"""
CREATE TABLE IF NOT EXISTS traffic_aggregates (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    interval_start          DATETIME(6)  NOT NULL,
    interval_end            DATETIME(6)  NOT NULL,
    interface               VARCHAR(96)  NOT NULL DEFAULT '',
    packet_count            BIGINT UNSIGNED NOT NULL DEFAULT 0,
    byte_count              BIGINT UNSIGNED NOT NULL DEFAULT 0,
    tcp_packets             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    udp_packets             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    icmp_packets            BIGINT UNSIGNED NOT NULL DEFAULT 0,
    arp_packets             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    other_packets           BIGINT UNSIGNED NOT NULL DEFAULT 0,
    unique_sources          INT UNSIGNED NOT NULL DEFAULT 0,
    unique_destinations     INT UNSIGNED NOT NULL DEFAULT 0,
    packets_per_second      DECIMAL(14,3) NOT NULL DEFAULT 0,
    bytes_per_second        DECIMAL(16,3) NOT NULL DEFAULT 0,
    dropped_packets         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_aggregate (interface, interval_start),
    KEY ix_aggregate_start (interval_start)
) {TABLE_OPTIONS}
"""

SNORT_ALERTS = f"""
CREATE TABLE IF NOT EXISTS snort_alerts (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_time          DATETIME(6)  NULL,
    received_at         DATETIME(6)  NOT NULL,
    time_source         VARCHAR(16)  NOT NULL DEFAULT 'snort',
    generator_id        INT UNSIGNED NULL,
    signature_id        INT UNSIGNED NULL,
    revision            INT UNSIGNED NULL,
    message             VARCHAR(512) NOT NULL DEFAULT '',
    classification      VARCHAR(128) NOT NULL DEFAULT '',
    priority            TINYINT UNSIGNED NULL,
    severity            VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    protocol            VARCHAR(16)  NOT NULL DEFAULT '',
    src_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    src_port            SMALLINT UNSIGNED NULL,
    dst_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    dst_port            SMALLINT UNSIGNED NULL,
    interface           VARCHAR(96)  NOT NULL DEFAULT '',
    sensor              VARCHAR(96)  NOT NULL DEFAULT '',
    transport           VARCHAR(16)  NOT NULL DEFAULT '',
    raw_alert           TEXT         NULL,
    src_host_id         BIGINT UNSIGNED NULL,
    dst_host_id         BIGINT UNSIGNED NULL,
    incident_id         BIGINT UNSIGNED NULL,
    status              VARCHAR(16)  NOT NULL DEFAULT 'NEW',
    evaluation          VARCHAR(20)  NOT NULL DEFAULT 'UNCLASSIFIED',
    evaluated_by        INT UNSIGNED NULL,
    evaluated_at        DATETIME(6)  NULL,
    duplicate_count     INT UNSIGNED NOT NULL DEFAULT 1,
    dedup_key           VARCHAR(190) NOT NULL DEFAULT '',
    created_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_alerts_time (alert_time),
    KEY ix_alerts_received (received_at),
    KEY ix_alerts_signature (signature_id),
    KEY ix_alerts_severity (severity),
    KEY ix_alerts_status (status),
    KEY ix_alerts_src (src_ip),
    KEY ix_alerts_dst (dst_ip),
    KEY ix_alerts_incident (incident_id),
    KEY ix_alerts_dedup (dedup_key, received_at),
    KEY ix_alerts_evaluation (evaluation),
    CONSTRAINT fk_alerts_src_host
        FOREIGN KEY (src_host_id) REFERENCES hosts (id) ON DELETE SET NULL,
    CONSTRAINT fk_alerts_dst_host
        FOREIGN KEY (dst_host_id) REFERENCES hosts (id) ON DELETE SET NULL,
    CONSTRAINT fk_alerts_incident
        FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE SET NULL,
    CONSTRAINT fk_alerts_evaluator
        FOREIGN KEY (evaluated_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

TRAFFIC_ANOMALIES = f"""
CREATE TABLE IF NOT EXISTS traffic_anomalies (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id             VARCHAR(48)  NOT NULL,
    category            VARCHAR(32)  NOT NULL DEFAULT 'UNCLASSIFIED',
    title               VARCHAR(190) NOT NULL,
    observation         TEXT         NULL,
    why_it_matters      TEXT         NULL,
    what_to_check       TEXT         NULL,
    severity            VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    confidence          TINYINT UNSIGNED NOT NULL DEFAULT 50,
    src_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    dst_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    dst_port            SMALLINT UNSIGNED NULL,
    protocol            VARCHAR(16)  NOT NULL DEFAULT '',
    interface           VARCHAR(96)  NOT NULL DEFAULT '',
    observed_value      DECIMAL(16,3) NOT NULL DEFAULT 0,
    threshold_value     DECIMAL(16,3) NOT NULL DEFAULT 0,
    window_seconds      INT UNSIGNED NOT NULL DEFAULT 0,
    event_count         INT UNSIGNED NOT NULL DEFAULT 1,
    first_seen          DATETIME(6)  NOT NULL,
    last_seen           DATETIME(6)  NOT NULL,
    evidence            TEXT         NULL,
    host_id             BIGINT UNSIGNED NULL,
    incident_id         BIGINT UNSIGNED NULL,
    evaluation          VARCHAR(20)  NOT NULL DEFAULT 'UNCLASSIFIED',
    source              VARCHAR(16)  NOT NULL DEFAULT 'PYSHARK',
    created_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_anomalies_created (created_at),
    KEY ix_anomalies_rule (rule_id),
    KEY ix_anomalies_src (src_ip),
    KEY ix_anomalies_dst (dst_ip),
    KEY ix_anomalies_severity (severity),
    KEY ix_anomalies_category (category),
    KEY ix_anomalies_incident (incident_id),
    CONSTRAINT fk_anomalies_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE SET NULL,
    CONSTRAINT fk_anomalies_incident
        FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

MITIGATION_RECOMMENDATIONS = f"""
CREATE TABLE IF NOT EXISTS mitigation_recommendations (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code                VARCHAR(64)  NOT NULL,
    threat_name         VARCHAR(190) NOT NULL,
    category            VARCHAR(32)  NOT NULL DEFAULT 'UNCLASSIFIED',
    severity            VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    applies_to_service  VARCHAR(64)  NOT NULL DEFAULT '',
    detection_source    VARCHAR(16)  NOT NULL DEFAULT '',
    explanation         TEXT         NULL,
    why_it_matters      TEXT         NULL,
    immediate_action    TEXT         NULL,
    long_term_action    TEXT         NULL,
    verification_steps  TEXT         NULL,
    reference_notes     TEXT         NULL,
    is_active           TINYINT(1)   NOT NULL DEFAULT 1,
    is_builtin          TINYINT(1)   NOT NULL DEFAULT 0,
    created_by          INT UNSIGNED NULL,
    updated_by          INT UNSIGNED NULL,
    created_at          DATETIME(6)  NOT NULL,
    updated_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_mitigation_code (code),
    KEY ix_mitigation_category (category),
    KEY ix_mitigation_active (is_active),
    CONSTRAINT fk_mitigation_created_by
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_mitigation_updated_by
        FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

INCIDENTS = f"""
CREATE TABLE IF NOT EXISTS incidents (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    reference               VARCHAR(32)  NOT NULL,
    title                   VARCHAR(190) NOT NULL,
    description             TEXT         NULL,
    category                VARCHAR(32)  NOT NULL DEFAULT 'UNCLASSIFIED',
    severity                VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    confidence              TINYINT UNSIGNED NOT NULL DEFAULT 0,
    status                  VARCHAR(20)  NOT NULL DEFAULT 'NEW',
    src_ip                  VARCHAR(45)  NOT NULL DEFAULT '',
    dst_ip                  VARCHAR(45)  NOT NULL DEFAULT '',
    dst_port                SMALLINT UNSIGNED NULL,
    protocol                VARCHAR(16)  NOT NULL DEFAULT '',
    affected_host_id        BIGINT UNSIGNED NULL,
    affected_host_ip        VARCHAR(45)  NOT NULL DEFAULT '',
    affected_service        VARCHAR(64)  NOT NULL DEFAULT '',
    correlation_key         VARCHAR(190) NOT NULL,
    evidence_sources        VARCHAR(96)  NOT NULL DEFAULT '',
    event_count             INT UNSIGNED NOT NULL DEFAULT 0,
    snort_alert_count       INT UNSIGNED NOT NULL DEFAULT 0,
    anomaly_count           INT UNSIGNED NOT NULL DEFAULT 0,
    finding_count           INT UNSIGNED NOT NULL DEFAULT 0,
    risk_score              INT UNSIGNED NOT NULL DEFAULT 0,
    risk_rationale          TEXT         NULL,
    detection_latency_seconds DECIMAL(12,3) NULL,
    first_seen              DATETIME(6)  NOT NULL,
    last_seen               DATETIME(6)  NOT NULL,
    created_at              DATETIME(6)  NOT NULL,
    updated_at              DATETIME(6)  NOT NULL,
    resolved_at             DATETIME(6)  NULL,
    assigned_user_id        INT UNSIGNED NULL,
    mitigation_id           BIGINT UNSIGNED NULL,
    evaluation              VARCHAR(20)  NOT NULL DEFAULT 'UNCLASSIFIED',
    evaluated_by            INT UNSIGNED NULL,
    evaluated_at            DATETIME(6)  NULL,
    -- Read/unread state for the sidebar counter: stamped the first time an
    -- analyst opens the investigation view, and never cleared afterwards.
    viewed_at               DATETIME(6)  NULL,
    viewed_by               INT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_reference (reference),
    KEY ix_incidents_viewed (viewed_at, status),
    KEY ix_incidents_status (status),
    KEY ix_incidents_severity (severity),
    KEY ix_incidents_created (created_at),
    KEY ix_incidents_last_seen (last_seen),
    KEY ix_incidents_correlation (correlation_key, status),
    KEY ix_incidents_src (src_ip),
    KEY ix_incidents_host (affected_host_id),
    KEY ix_incidents_assigned (assigned_user_id),
    CONSTRAINT fk_incidents_host
        FOREIGN KEY (affected_host_id) REFERENCES hosts (id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_user
        FOREIGN KEY (assigned_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_mitigation
        FOREIGN KEY (mitigation_id)
        REFERENCES mitigation_recommendations (id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_evaluator
        FOREIGN KEY (evaluated_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_viewer
        FOREIGN KEY (viewed_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

INCIDENT_EVENTS = f"""
CREATE TABLE IF NOT EXISTS incident_events (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id         BIGINT UNSIGNED NOT NULL,
    source              VARCHAR(16)  NOT NULL DEFAULT 'CORRELATION',
    event_type          VARCHAR(48)  NOT NULL DEFAULT '',
    reference_table     VARCHAR(48)  NOT NULL DEFAULT '',
    reference_id        BIGINT UNSIGNED NULL,
    occurred_at         DATETIME(6)  NULL,
    summary             VARCHAR(512) NOT NULL DEFAULT '',
    detail              TEXT         NULL,
    created_at          DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_event (incident_id, reference_table, reference_id),
    KEY ix_incident_events_incident (incident_id),
    KEY ix_incident_events_occurred (occurred_at),
    CONSTRAINT fk_incident_events_incident
        FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

INCIDENT_NOTES = f"""
CREATE TABLE IF NOT EXISTS incident_notes (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id     BIGINT UNSIGNED NOT NULL,
    user_id         INT UNSIGNED NULL,
    note            TEXT         NOT NULL,
    created_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_incident_notes_incident (incident_id),
    CONSTRAINT fk_incident_notes_incident
        FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_notes_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

THREAT_MITIGATION_MAPPING = f"""
CREATE TABLE IF NOT EXISTS threat_mitigation_mapping (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    category                VARCHAR(32)  NOT NULL,
    recommendation_id       BIGINT UNSIGNED NOT NULL,
    priority                INT UNSIGNED NOT NULL DEFAULT 100,
    condition_service       VARCHAR(64)  NOT NULL DEFAULT '',
    condition_min_severity  VARCHAR(16)  NOT NULL DEFAULT '',
    is_active               TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_threat_mapping (category, recommendation_id, condition_service),
    KEY ix_threat_mapping_category (category, priority),
    CONSTRAINT fk_threat_mapping_recommendation
        FOREIGN KEY (recommendation_id)
        REFERENCES mitigation_recommendations (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

REPORTS = f"""
CREATE TABLE IF NOT EXISTS reports (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    report_type         VARCHAR(32)  NOT NULL,
    title               VARCHAR(190) NOT NULL,
    export_format       VARCHAR(8)   NOT NULL DEFAULT 'PDF',
    file_path           VARCHAR(512) NOT NULL DEFAULT '',
    period_start        DATETIME(6)  NULL,
    period_end          DATETIME(6)  NULL,
    scope               VARCHAR(255) NOT NULL DEFAULT '',
    record_counts       TEXT         NULL,
    generated_by        INT UNSIGNED NULL,
    generated_at        DATETIME(6)  NOT NULL,
    file_size_bytes     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY ix_reports_generated (generated_at),
    KEY ix_reports_type (report_type),
    KEY ix_reports_user (generated_by),
    CONSTRAINT fk_reports_user
        FOREIGN KEY (generated_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

SYSTEM_SETTINGS = f"""
CREATE TABLE IF NOT EXISTS system_settings (
    setting_key     VARCHAR(96)  NOT NULL,
    setting_value   VARCHAR(512) NOT NULL DEFAULT '',
    value_type      VARCHAR(16)  NOT NULL DEFAULT 'str',
    category        VARCHAR(32)  NOT NULL DEFAULT 'general',
    description     VARCHAR(512) NOT NULL DEFAULT '',
    updated_by      INT UNSIGNED NULL,
    updated_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (setting_key),
    KEY ix_settings_category (category),
    CONSTRAINT fk_settings_user
        FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

INTEGRATION_STATUS = f"""
CREATE TABLE IF NOT EXISTS integration_status (
    name            VARCHAR(48)  NOT NULL,
    state           VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN',
    detail          VARCHAR(512) NOT NULL DEFAULT '',
    last_checked    DATETIME(6)  NULL,
    last_success    DATETIME(6)  NULL,
    last_error      VARCHAR(512) NOT NULL DEFAULT '',
    metadata        TEXT         NULL,
    PRIMARY KEY (name)
) {TABLE_OPTIONS}
"""

NOTIFICATIONS = f"""
CREATE TABLE IF NOT EXISTS notifications (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED NULL,
    level           VARCHAR(16)  NOT NULL DEFAULT 'INFO',
    title           VARCHAR(190) NOT NULL,
    message         VARCHAR(512) NOT NULL DEFAULT '',
    category        VARCHAR(32)  NOT NULL DEFAULT 'system',
    reference_type  VARCHAR(48)  NOT NULL DEFAULT '',
    reference_id    BIGINT UNSIGNED NULL,
    is_read         TINYINT(1)   NOT NULL DEFAULT 0,
    created_at      DATETIME(6)  NOT NULL,
    read_at         DATETIME(6)  NULL,
    PRIMARY KEY (id),
    KEY ix_notifications_user (user_id, is_read),
    KEY ix_notifications_created (created_at),
    CONSTRAINT fk_notifications_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

NOTIFICATION_READS = f"""
CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id BIGINT UNSIGNED NOT NULL,
    user_id         INT UNSIGNED    NOT NULL,
    read_at         DATETIME(6)     NOT NULL,
    PRIMARY KEY (notification_id, user_id),
    KEY ix_notification_reads_user (user_id),
    CONSTRAINT fk_notification_reads_notification
        FOREIGN KEY (notification_id) REFERENCES notifications (id) ON DELETE CASCADE,
    CONSTRAINT fk_notification_reads_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

APP_ERRORS = f"""
CREATE TABLE IF NOT EXISTS app_errors (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    component       VARCHAR(64)  NOT NULL,
    message         VARCHAR(512) NOT NULL,
    detail          TEXT         NULL,
    severity        VARCHAR(16)  NOT NULL DEFAULT 'ERROR',
    occurred_at     DATETIME(6)  NOT NULL,
    acknowledged    TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY ix_errors_occurred (occurred_at),
    KEY ix_errors_component (component),
    KEY ix_errors_ack (acknowledged)
) {TABLE_OPTIONS}
"""

EVALUATION_RUNS = f"""
CREATE TABLE IF NOT EXISTS evaluation_runs (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    reference               VARCHAR(32)  NOT NULL,
    scenario                VARCHAR(32)  NOT NULL,
    repetition              INT UNSIGNED NOT NULL DEFAULT 1,
    attacker_ip             VARCHAR(45)  NOT NULL DEFAULT '',
    target_ip               VARCHAR(45)  NOT NULL DEFAULT '',
    initiated_at            DATETIME(6)  NOT NULL,
    initiation_source       VARCHAR(32)  NOT NULL DEFAULT '',
    ended_at                DATETIME(6)  NULL,
    grace_seconds           INT UNSIGNED NOT NULL DEFAULT 60,
    status                  VARCHAR(16)  NOT NULL DEFAULT 'RUNNING',
    outcome                 VARCHAR(24)  NOT NULL DEFAULT 'PENDING',
    first_alert_at          DATETIME(6)  NULL,
    first_alert_stored_at   DATETIME(6)  NULL,
    first_alert_source      VARCHAR(16)  NOT NULL DEFAULT '',
    first_alert_reference   VARCHAR(64)  NOT NULL DEFAULT '',
    detection_time_seconds  DECIMAL(12,3) NULL,
    stored_time_seconds     DECIMAL(12,3) NULL,
    detections_total        INT UNSIGNED NOT NULL DEFAULT 0,
    detections_matching     INT UNSIGNED NOT NULL DEFAULT 0,
    classification_correct  TINYINT(1)   NULL,
    notes                   TEXT         NULL,
    started_by              INT UNSIGNED NULL,
    completed_by            INT UNSIGNED NULL,
    created_at              DATETIME(6)  NOT NULL,
    updated_at              DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_evaluation_runs_reference (reference),
    KEY ix_evaluation_runs_scenario (scenario, status),
    KEY ix_evaluation_runs_initiated (initiated_at),
    CONSTRAINT fk_evaluation_runs_starter
        FOREIGN KEY (started_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_evaluation_runs_completer
        FOREIGN KEY (completed_by) REFERENCES users (id) ON DELETE SET NULL
) {TABLE_OPTIONS}
"""

EVALUATION_RUN_DETECTIONS = f"""
CREATE TABLE IF NOT EXISTS evaluation_run_detections (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id              BIGINT UNSIGNED NOT NULL,
    source              VARCHAR(16)  NOT NULL,
    reference_table     VARCHAR(32)  NOT NULL,
    reference_id        BIGINT UNSIGNED NOT NULL,
    category            VARCHAR(32)  NOT NULL DEFAULT '',
    severity            VARCHAR(16)  NOT NULL DEFAULT '',
    src_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    dst_ip              VARCHAR(45)  NOT NULL DEFAULT '',
    generated_at        DATETIME(6)  NULL,
    stored_at           DATETIME(6)  NOT NULL,
    matches_scenario    TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uq_evaluation_detection (run_id, reference_table, reference_id),
    CONSTRAINT fk_evaluation_detection_run
        FOREIGN KEY (run_id) REFERENCES evaluation_runs (id) ON DELETE CASCADE
) {TABLE_OPTIONS}
"""

#: Ordered DDL, respecting foreign-key dependencies.
CREATE_TABLE_STATEMENTS: tuple[tuple[str, str], ...] = (
    ("schema_migrations", SCHEMA_MIGRATIONS),
    ("roles", ROLES),
    ("permissions", PERMISSIONS),
    ("role_permissions", ROLE_PERMISSIONS),
    ("users", USERS),
    ("login_attempts", LOGIN_ATTEMPTS),
    ("sessions", SESSIONS),
    ("password_reset_requests", PASSWORD_RESET_REQUESTS),
    ("audit_logs", AUDIT_LOGS),
    ("hosts", HOSTS),
    ("host_observations", HOST_OBSERVATIONS),
    ("trusted_hosts", TRUSTED_HOSTS),
    ("scans", SCANS),
    ("scan_hosts", SCAN_HOSTS),
    ("ports", PORTS),
    ("scan_findings", SCAN_FINDINGS),
    ("vuln_knowledge", VULN_KNOWLEDGE),
    ("traffic_records", TRAFFIC_RECORDS),
    ("traffic_aggregates", TRAFFIC_AGGREGATES),
    ("mitigation_recommendations", MITIGATION_RECOMMENDATIONS),
    ("incidents", INCIDENTS),
    ("snort_alerts", SNORT_ALERTS),
    ("traffic_anomalies", TRAFFIC_ANOMALIES),
    ("incident_events", INCIDENT_EVENTS),
    ("incident_notes", INCIDENT_NOTES),
    ("threat_mitigation_mapping", THREAT_MITIGATION_MAPPING),
    ("reports", REPORTS),
    ("system_settings", SYSTEM_SETTINGS),
    ("integration_status", INTEGRATION_STATUS),
    ("notifications", NOTIFICATIONS),
    ("notification_reads", NOTIFICATION_READS),
    ("app_errors", APP_ERRORS),
    ("evaluation_runs", EVALUATION_RUNS),
    ("evaluation_run_detections", EVALUATION_RUN_DETECTIONS),
)

#: Every table AETHRA-SEC requires; used by the schema diagnostics check.
REQUIRED_TABLES: tuple[str, ...] = tuple(name for name, _ in CREATE_TABLE_STATEMENTS)

#: Tables that hold security evidence and must never be truncated casually.
EVIDENCE_TABLES: tuple[str, ...] = (
    "audit_logs",
    "snort_alerts",
    "scan_findings",
    "traffic_anomalies",
    "incidents",
    "incident_events",
    "evaluation_runs",
    "evaluation_run_detections",
)
