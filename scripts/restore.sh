#!/usr/bin/env bash
# Restores a backup made by backup.sh. This REPLACES the current database
# contents, so it insists on --yes.
#
#   scripts/restore.sh backups/mancar-20260101T030000Z.sql.gz --yes
set -euo pipefail

cd "${MANCAR_DIR:-$(dirname "$0")/..}"
COMPOSE=${COMPOSE:-docker compose}

FILE=${1:-}
CONFIRM=${2:-}
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "usage: $0 BACKUP_FILE.sql.gz --yes" >&2
  exit 2
fi
if [ "$CONFIRM" != "--yes" ]; then
  echo "This replaces the current database with $FILE. Re-run with --yes to continue." >&2
  exit 2
fi
gzip -t "$FILE" || { echo "$FILE is not a valid gzip file" >&2; exit 1; }

val() { # value of KEY in .env, empty when absent
  if [ -f .env ]; then grep -E "^$1=" .env | head -n1 | cut -d= -f2- || true; fi
}
DB_USER=$(val POSTGRES_USER); DB_USER=${DB_USER:-mancar}
DB_NAME=$(val POSTGRES_DB);   DB_NAME=${DB_NAME:-mancar}

echo "stopping the gateway (agents will reconnect when it is back)"
$COMPOSE stop gateway
trap '$COMPOSE start gateway' EXIT

gunzip -c "$FILE" | $COMPOSE exec -T postgres psql -q -o /dev/null -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME"
echo "restore complete"
