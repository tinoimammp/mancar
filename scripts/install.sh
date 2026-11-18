#!/bin/sh
# Installs the latest mancar client on macOS or Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/tinoimammp/mancar/main/scripts/install.sh | sh
#
# It picks the build for this system, checks it against the release's
# SHA256SUMS and installs it to /usr/local/bin (with sudo when needed), or to
# MANCAR_INSTALL_DIR when set.
set -eu

BASE=https://github.com/tinoimammp/mancar/releases/latest/download
DIR=${MANCAR_INSTALL_DIR:-/usr/local/bin}

die() { echo "mancar install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) OS=darwin ;;
  Linux) OS=linux ;;
  *) die "no build for $(uname -s); see https://github.com/tinoimammp/mancar/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  arm64 | aarch64) ARCH=arm64 ;;
  *) die "no build for $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || die "cannot download the release list"
FILE=$(grep -o "mancar-v[^ ]*-$OS-$ARCH\$" "$TMP/SHA256SUMS" | head -n 1)
[ -n "$FILE" ] || die "the latest release has no build for $OS/$ARCH"
echo "Downloading $FILE ..."
curl -fsSL -o "$TMP/mancar" "$BASE/$FILE" || die "download failed"

WANT=$(grep " $FILE\$" "$TMP/SHA256SUMS" | cut -d ' ' -f 1)
if command -v sha256sum >/dev/null 2>&1; then
  GOT=$(sha256sum "$TMP/mancar" | cut -d ' ' -f 1)
else
  GOT=$(shasum -a 256 "$TMP/mancar" | cut -d ' ' -f 1)
fi
[ "$GOT" = "$WANT" ] || die "checksum mismatch; nothing was installed"
chmod 755 "$TMP/mancar"

if [ -d "$DIR" ] && [ -w "$DIR" ]; then
  mv "$TMP/mancar" "$DIR/mancar"
elif command -v sudo >/dev/null 2>&1; then
  echo "Installing to $DIR (asks for your password) ..."
  sudo mkdir -p "$DIR"
  sudo mv "$TMP/mancar" "$DIR/mancar"
else
  die "cannot write to $DIR; run again with MANCAR_INSTALL_DIR=\$HOME/.local/bin"
fi

echo "Installed $DIR/mancar"
"$DIR/mancar" version || true
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "Note: $DIR is not on your PATH; add it, or run $DIR/mancar" ;;
esac
echo "Next: mancar login https://YOUR_SERVER"
