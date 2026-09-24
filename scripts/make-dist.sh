#!/bin/sh
# make-dist.sh — assemble release tarballs from a built target directory.
#
#   scripts/make-dist.sh <target-name> [cargo-profile-dir]
#
# Produces dist/tethys-<version>-<target>.tar.gz (+ .sha256) with the layout
# install.sh expects:
#
#   tethys-<version>-<target>/
#     bin/tethysd  bin/tethys-mcp  bin/tethys
#     share/tethys/baseline.nft
#     share/tethys/tethysd.service
#     share/tethys/tethys-baseline.service
#     share/tethys/config.example.toml
set -eu

cd "$(dirname "$0")/.."
TARGET="${1:?usage: make-dist.sh <target-name> [profile-dir]}"
PROFILE="${2:-release}"
VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)
PKG="tethys-${VERSION}-${TARGET}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }
need tar
need sha256sum

TGT="target/${TARGET}/${PROFILE}"
[ -x "$TGT/tethysd" ] || { echo "build first: cargo build --release --target $TARGET" >&2; exit 1; }

STAGE="dist/$PKG"
rm -rf "$STAGE" "$STAGE.tar.gz" "$STAGE.tar.gz.sha256"
mkdir -p "$STAGE/bin" "$STAGE/share/tethys"
install -m 0755 "$TGT/tethysd" "$TGT/tethys-mcp" "$TGT/tethys" "$STAGE/bin/"
install -m 0644 deploy/tethys-baseline.nft "$STAGE/share/tethys/baseline.nft"
install -m 0644 deploy/tethysd.service deploy/tethys-baseline.service "$STAGE/share/tethys/"
install -m 0644 config.example.toml "$STAGE/share/tethys/"
install -m 0755 install.sh uninstall.sh "$STAGE/"
tar -czf "dist/$PKG.tar.gz" -C dist "$PKG"
( cd dist && sha256sum "$PKG.tar.gz" > "$PKG.tar.gz.sha256" )
rm -rf "$STAGE"
echo "dist/$PKG.tar.gz"
echo "dist/$PKG.tar.gz.sha256"
