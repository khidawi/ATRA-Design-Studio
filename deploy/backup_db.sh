#!/bin/sh
# An encrypted backup of the ASTRA database (production compose file).
#
#   BACKUP_PASSPHRASE_FILE=/secure/place/astra-backup.pass ./backup_db.sh [astra-2026-11-03.dump.enc]
#
# The dump is encrypted with AES-256 (key derived from the passphrase, 200,000 rounds) before it is written, so the file on disk, on a backup server or in cloud storage is
# unreadable without the passphrase. Keep the passphrase apart from the backups and from .env, and keep ASTRA_SECRET_KEY somewhere safe too: without it the repository tokens,
# identity-provider credentials and webhook addresses in a restored copy cannot be read again.
set -eu
cd "$(dirname "$0")"
: "${BACKUP_PASSPHRASE_FILE:?set BACKUP_PASSPHRASE_FILE to a file that holds the passphrase}"
[ -s "$BACKUP_PASSPHRASE_FILE" ] || { echo "The passphrase file is empty or missing."; exit 2; }
OUT="${1:-astra-$(date +%Y%m%d-%H%M%S).dump.enc}"
OWNER_PW=$(grep '^ASTRA_DB_OWNER_PASSWORD=' .env | cut -d= -f2-)
umask 077
docker compose -f docker-compose.prod.yml exec -T -e PGPASSWORD="$OWNER_PW" db pg_dump -U stai_owner -d stai -Fc \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:"$BACKUP_PASSPHRASE_FILE" -out "$OUT"
[ -s "$OUT" ] || { echo "The backup is empty: something failed."; rm -f "$OUT"; exit 1; }
echo "Wrote $OUT ($(wc -c < "$OUT") bytes, encrypted). Test a restore into a scratch database with ./restore_db.sh $OUT before you rely on it."
