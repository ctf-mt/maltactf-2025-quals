#!/bin/sh

ROOTFS=$(mktemp -d)
FLAG=$(mktemp)

echo hi

cd /home/user/
cp -r contents "$ROOTFS"
export TMPDIR="/tmp/"
qemu-system-x86_64 \
    -m 64M \
    -drive file=fat:rw:"$ROOTFS/contents",format=raw \
    -net none \
    -bios OVMF.fd \
    -serial stdio \
    -monitor /dev/null \
    -nographic \
    -no-reboot