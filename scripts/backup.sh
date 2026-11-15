#!/usr/bin/env bash
# Dumps the database to backups/mancar-<UTC timestamp>.sql.gz and keeps the
# newest BACKUP_RETAIN files (default 14). Run it from cron, for example:
#   17 3 * * *  /opt/mancar/scripts/backup.sh
#
# What to back up: the database (this script) and the .env file (store it
# separately and securely: it holds the secrets). The caddy_data volume holds
# the TLS certificates; they can be re-issued, so it is optional.
set -euo pipefail

cd "${MANCAR_DIR:-$(dirname "$0")/..}"
COMPOSE=${COMPOSE:-docker compose}
DEST=${BACKUP_DIR:-backups}
RETAIN=${BACKUP_RETAIN:-14}

val() { # value of KEY in .env, empty when absent
  if [ -f .env ]; then grep -E "^$1=" .env | head -n1 | cut -d= -f2- || true; fi
}
DB_USER=$(val POSTGRES_USER); DB_USER=${DB_USER:-mancar}
DB_NAME=$(val POSTGRES_DB);   DB_NAME=${DB_NAME:-mancar}

umask 077
mkdir -p "$DEST"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$DEST/mancar-$STAMP.sql.gz"
TMP="$OUT.partial"
trap 'rm -f "$TMP"' EXIT

# pipefail makes a failing pg_dump fail the whole backup instead of leaving a
# truncated file that looks fine.
$COMPOSE exec -T postgres pg_dump -U "$DB_USER" -d "$DB_NAME" --clean --if-exists --no-owner | gzip >"$TMP"

gzip -t "$TMP"
if [ "$(wc -c <"$TMP")" -lt 200 ]; then
  echo "backup is suspiciously small; refusing to keep it" >&2
  exit 1
fi
mv "$TMP" "$OUT"
trap - EXIT
echo "wrote $OUT ($(wc -c <"$OUT") bytes)"

# Prune the oldest backups beyond RETAIN.
# shellcheck disable=SC2012
ls -1t "$DEST"/mancar-*.sql.gz 2>/dev/null | tail -n +"$((RETAIN + 1))" | while read -r old; do
  rm -f "$old" && echo "removed old backup $old"
done
