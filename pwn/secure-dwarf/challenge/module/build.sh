set -e

zig build-obj dwarf.zig -femit-bin=dwarf.o -OReleaseFast -mcmodel=kernel -mcpu=x86_64-sse-sse2-avx-avx2
make -C ../linux M="$PWD" modules