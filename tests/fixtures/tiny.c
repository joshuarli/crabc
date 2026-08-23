// Tiny PIE program: raw syscalls, no libc dependency.
// Prints "Hello\n" via SYS_write, exits 0 via SYS_exit.

static void my_write(int fd, const void *buf, unsigned long count) {
    register long x8 __asm__("x8") = 64;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = count;
    __asm__ volatile (
        "svc #0"
        :
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2)
        : "memory"
    );
}

static void my_exit(int code) {
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = code;
    __asm__ volatile (
        "svc #0"
        :
        : "r"(x8), "r"(x0)
        : "memory"
    );
    __builtin_unreachable();
}

void _start(void) {
    my_write(1, "Hello\n", 6);
    my_exit(0);
}
