#!/usr/bin/env bash
#
# Backup AXT-Term's database.
#
# Uses VACUUM INTO through axt-admin, which produces a transactionally consistent
# copy while the service keeps running — so there is no maintenance window and no
# risk of copying a half-written page.
#
# Usage:
#   scripts/backup.sh [destination-directory] [retention-days]

set -Eeuo pipefail

DEST="${1:-./backups}"
RETENTION_DAYS="${2:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="axt-term-${STAMP}.db"
CONTAINER_PATH="/var/lib/axt-term/${NAME}"

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker is not available"
mkdir -p "$DEST"

log "creating backup inside the container"
docker compose exec -T axt-term axt-admin backup --out "$CONTAINER_PATH" \
  || fail "axt-admin backup failed"

log "copying to ${DEST}/${NAME}"
docker compose cp "axt-term:${CONTAINER_PATH}" "${DEST}/${NAME}" \
  || fail "could not copy the backup out of the container"

# Remove the in-container copy so the data volume does not accumulate backups.
docker compose exec -T axt-term rm -f "$CONTAINER_PATH" || true

# Verify rather than assume. An unverified backup is a guess.
if command -v sqlite3 >/dev/null; then
  log "verifying integrity"
  result="$(sqlite3 "${DEST}/${NAME}" 'PRAGMA integrity_check;' || echo 'failed')"
  [[ "$result" == "ok" ]] || fail "integrity check returned: ${result}"

  hosts="$(sqlite3 "${DEST}/${NAME}" 'SELECT COUNT(*) FROM hosts;' 2>/dev/null || echo '?')"
  creds="$(sqlite3 "${DEST}/${NAME}" 'SELECT COUNT(*) FROM credentials;' 2>/dev/null || echo '?')"
  log "verified: ${hosts} hosts, ${creds} credentials"
else
  log "sqlite3 is not installed; skipping verification (install it to enable this)"
fi

size="$(du -h "${DEST}/${NAME}" | cut -f1)"
log "backup complete: ${DEST}/${NAME} (${size})"

if (( RETENTION_DAYS > 0 )); then
  log "pruning backups older than ${RETENTION_DAYS} days"
  find "$DEST" -name 'axt-term-*.db' -type f -mtime "+${RETENTION_DAYS}" -print -delete || true
fi

cat <<'REMINDER'

  The master key is NOT in this backup, by design.

  Back up secrets/axt_master_key separately and store it somewhere else. A single
  archive containing both the database and the key is a backup of your plaintext
  credentials, which defeats the encryption entirely.

REMINDER
