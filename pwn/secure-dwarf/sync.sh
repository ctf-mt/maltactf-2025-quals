#!/bin/sh

set -e

NAME="secure-dwarf"
TMP="./tmp"
ROOTFS="$TMP/rootfs"
DIST="$TMP/$NAME"

mkdir -p "$TMP"
mkdir -p "$DIST"
pwnc kernel decompress --initramfs challenge/initramfs.cpio.gz --rootfs "$ROOTFS"
echo "maltactf{teemo}" > "$ROOTFS"/root/flag.txt
rm "$ROOTFS"/bin/pwn
pwnc kernel compress --initramfs "$DIST/initramfs.cpio.gz" --rootfs "$ROOTFS" --gzipped
cp challenge/linux/.config "$DIST"
cp challenge/bzImage "$DIST"
cp challenge/module/dwarf.zig "$DIST"
cp challenge/module/kernel.zig "$DIST"
cp challenge/run.sh "$DIST"
cp challenge/Dockerfile "$DIST"

cd "$TMP" && tar -czf ../attachments/dist.tar.gz "$NAME" && cd ..