#!/usr/bin/env bash
# First-time setup: creates .env from .env.example and generates the three
# secrets. Safe to run again: a value that is already set is never replaced
# (regenerating ENCRYPTION_KEY or POSTGRES_PASSWORD would lock you out of
# your own data).
set -euo pipefail

cd "${MANCAR_DIR:-$(dirname "$0")/..}"
ENV_FILE=${ENV_FILE:-.env}

if [ ! -f "$ENV_FILE" ]; then
  cp .env.example "$ENV_FILE"
  echo "created $ENV_FILE from .env.example"
fi
chmod 600 "$ENV_FILE"

rand_hex() { # 32 random bytes as 64 hex characters
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

get() { grep -E "^$1=" "$ENV_FILE" | head -n1 | cut -d= -f2- || true; }

set_value() { # key value: replace the line, or append when the key is absent
  local tmp
  tmp=$(mktemp "${ENV_FILE}.XXXXXX")
  chmod 600 "$tmp"
  if grep -qE "^$1=" "$ENV_FILE"; then
    VALUE=$2 awk -v key="$1" 'BEGIN{FS=OFS="="} $1==key && !done {print key "=" ENVIRON["VALUE"]; done=1; next} {print}' "$ENV_FILE" >"$tmp"
  else
    cat "$ENV_FILE" >"$tmp"; printf '%s=%s\n' "$1" "$2" >>"$tmp"
  fi
  mv "$tmp" "$ENV_FILE"
}

for key in JWT_SECRET ENCRYPTION_KEY POSTGRES_PASSWORD; do
  if [ -z "$(get "$key")" ]; then
    set_value "$key" "$(rand_hex)"
    echo "generated $key"
  else
    echo "kept the existing $key"
  fi
done

missing=()
for key in BASE_DOMAIN ACME_EMAIL CLOUDFLARE_API_TOKEN; do
  [ -n "$(get "$key")" ] || missing+=("$key")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo
  echo "Still to fill in by hand in $ENV_FILE: ${missing[*]}"
  echo "Then start everything with: docker compose up -d"
else
  echo
  echo "$ENV_FILE is complete. Start everything with: docker compose up -d"
fi
