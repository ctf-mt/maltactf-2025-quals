#!/bin/sh

cd /home/user/
qemu-system-x86_64 \
    -cpu qemu64,+smep,+smap \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "init=/init console=ttyS0 earlycon oops=panic loglevel=0 panic_on_warn=1 panic=-1" \
    -m 256M \
    -no-reboot \
    -nographic \
    -monitor /dev/null
