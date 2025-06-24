all:
	cd module && ./build.sh
	cp module/dwarf.ko rootfs/dwarf.ko
	# zig cc test.c -o rootfs/bin/pwn -target x86_64-linux-musl -O1 -static -s -ffunction-sections -fdata-sections -flto
	zig build-exe test.zig -femit-bin=rootfs/bin/pwn -target x86_64-linux-musl -OReleaseSmall -static -fstrip -flto
	pwnc kernel compress --rootfs rootfs --initramfs initramfs.cpio.gz