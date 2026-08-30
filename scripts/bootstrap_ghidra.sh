#!/usr/bin/env bash
set -euo pipefail
VERSION="12.1.3"
DATE="20260817"
SHA256="93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
ASSET="ghidra_${VERSION}_PUBLIC_${DATE}.zip"
TAG="Ghidra_${VERSION}_build"
URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/${TAG}/${ASSET}"
DEST="${1:-$HOME/.local/share/unirevlab}"
mkdir -p "$DEST"
ZIP="$DEST/$ASSET"
if [[ ! -f "$ZIP" ]]; then
  curl --fail --location --retry 3 --output "$ZIP" "$URL"
fi
echo "$SHA256  $ZIP" | sha256sum --check --status || { echo "Ghidra checksum mismatch" >&2; exit 1; }
INSTALL="$DEST/ghidra_${VERSION}_PUBLIC"
if [[ ! -d "$INSTALL" ]]; then
  unzip -q "$ZIP" -d "$DEST"
fi
python3 -m pip install --user --no-index -f "$INSTALL/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
printf '%s\n' "$INSTALL"
