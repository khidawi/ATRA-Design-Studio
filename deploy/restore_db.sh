#!/bin/sh
# Restores an encrypted backup (from backup_db.sh) into a NEW database, so a backup can be tested, or inspected, without touching the live one.
#
#   BACKUP_PASSPHRASE_FILE=/secure/place/astra-backup.pass ./restore_db.sh astra-2026-11-03.dump.enc [astra_restore_check]
#
# It creates the database (default name astra_restore_check), restores into it as stai_owner, and prints how many tables and audit events it holds. It never replaces the live
# database: to recover, stop the API, restore into a fresh volume or a new database, then point DATABASE_URL at it.
set -eu
cd "$(dirname "$0")"
: "${BACKUP_PASSPHRASE_FILE:?set BACKUP_PASSPHRASE_FILE to a file that holds the passphrase}"
FILE="${1:?give the backup file}"
DB="${2:-astra_restore_check}"
case "$DB" in stai) echo "Refusing to restore over the live database. Choose another name."; exit 2;; *[!a-z0-9_]*) echo "Use lower-case letters, digits and underscore."; exit 2;; esac
ADMIN_PW=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)
OWNER_PW=$(grep '^ASTRA_DB_OWNER_PASSWORD=' .env | cut -d= -f2-)
DC="docker compose -f docker-compose.prod.yml exec -T"
$DC -e PGPASSWORD="$ADMIN_PW" db psql -U astra_admin -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS $DB" -c "CREATE DATABASE $DB OWNER stai_owner"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"$BACKUP_PASSPHRASE_FILE" -in "$FILE" \
  | $DC -e PGPASSWORD="$OWNER_PW" db pg_restore -U stai_owner -d "$DB" --no-owner --role=stai_owner
$DC -e PGPASSWORD="$OWNER_PW" db psql -U stai_owner -d "$DB" -tA -c "SELECT 'tables: ' || count(*) FROM information_schema.tables WHERE table_schema = 'public'" -c "SELECT 'audit events: ' || count(*) FROM audit_events"
echo "Restored into database $DB. Drop it when you are done: docker compose -f docker-compose.prod.yml exec -T -e PGPASSWORD=... db psql -U astra_admin -d postgres -c 'DROP DATABASE $DB'"
