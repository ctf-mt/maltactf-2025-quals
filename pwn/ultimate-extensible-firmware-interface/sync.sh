#!/bin/sh

set -e

NAME="ultimate-extensible-firmware-interface"
TMP="./tmp"
ROOTFS="$TMP/rootfs"
DIST="$TMP/$NAME"

mkdir -p "$TMP"
mkdir -p "$DIST"
cp -r challenge/contents "$DIST"
cp challenge/run.sh "$DIST"
cp challenge/OVMF.fd "$DIST"
cp challenge/Dockerfile "$DIST"
cp challenge/README.md "$DIST"
cp challenge/build.zig "$DIST"
cp -r challenge/src "$DIST"
echo "maltactf{teemo}" > "$DIST"/contents/flag.txt

cd "$TMP" && tar -czf ../attachments/dist.tar.gz "$NAME" && cd ..