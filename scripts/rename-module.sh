#!/usr/bin/env bash
# Replaces the placeholder module path (github.com/USERNAME/mancar) with
# yours everywhere: go.mod, every import, the Dockerfile, docs and workflows.
#
#   scripts/rename-module.sh github.com/acme/tunnel
set -euo pipefail

cd "${MANCAR_DIR:-$(dirname "$0")/..}"
OLD=github.com/USERNAME/mancar
NEW=${1:-}
if ! [[ "$NEW" =~ ^[a-z0-9.-]+\.[a-z]{2,}/[A-Za-z0-9._/-]+$ ]]; then
  echo "usage: $0 github.com/OWNER/REPO   (a valid Go module path)" >&2
  exit 2
fi
if [ "$NEW" = "$OLD" ]; then echo "already $OLD"; exit 0; fi

# Escape characters that are special in the sed replacement.
esc_old=$(printf '%s' "$OLD" | sed 's/[.[\*^$/]/\\&/g')
esc_new=$(printf '%s' "$NEW" | sed 's/[&/\]/\\&/g')

grep -rlI --exclude-dir=.git --exclude-dir=dist --exclude=go.sum "$OLD" . | while read -r f; do
  sed -i.bak "s/$esc_old/$esc_new/g" "$f" && rm -f "$f.bak"
  echo "updated $f"
done
echo
echo "Module path is now $NEW."
echo "Also set MANCAR_IMAGE / MANCAR_EDGE_IMAGE in .env to your registry, and run: go build ./... && go test ./..."
