#!/usr/bin/env bash
# Daily backup of the registrations database. Run via cron as the
# aethra-reg user, e.g.:
#   0 3 * * * /opt/aethra-registration/web/registration_api/deploy/backup-registrations.sh
#
# Uses `sqlite3 .backup` rather than `cp` - it's just as simple to invoke
# but is safe against a copy landing mid-write, which a plain cp is not.
set -euo pipefail

DB_PATH="/var/lib/aethra-registration/registrations.db"
BACKUP_DIR="/var/backups/aethra-registration"
RETENTION_DAYS=14

mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/registrations-$(date +%F).db'"
find "$BACKUP_DIR" -name 'registrations-*.db' -mtime +$RETENTION_DAYS -delete
