pub fn hang() noreturn {
    while (true) {
        asm volatile (
            \\hlt
            ::: "memory");
    }
}
