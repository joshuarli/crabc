extern int mid_value(void);
extern int mid_initializers_ran(void);
extern int mid_leaf_relro_write_signal(void);
static int main_private;
/* This object must be in PT_GNU_RELRO after its RELATIVE relocation. */
static int *main_relro_pointer __attribute__((section(".data.rel.ro"))) = &main_private;

static long syscall1(long number, long argument) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument) : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long one, long two, long three, long four) {
    long result;
    register long r10 __asm__("r10") = four;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(one), "S"(two), "d"(three), "r"(r10) : "rcx", "r11", "memory");
    return result;
}

static int relro_write_signal(void) {
    long child = syscall1(57, 0); /* fork */
    if (child == 0) {
        int *volatile *slot = (int *volatile *)(void *)&main_relro_pointer;
        *slot = &main_private;
        return 1;
    }
    if (child < 0) return 0;
    int status = 0;
    if (syscall4(61, child, (long)&status, 0, 0) != child) return 0; /* wait4 */
    return status & 0x7f;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (mid_value() != 42 || !mid_initializers_ran()) return 41;
    if (relro_write_signal() != 11) return 42;
    return mid_leaf_relro_write_signal() == 11 ? 0 : 43;
}
