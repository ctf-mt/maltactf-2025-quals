#!/bin/bash

qemu-system-x86_64 \
    -m 256M \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 quiet loglevel=0 kaslr kpti=1 pti=on panic=-1 oops=panic"
