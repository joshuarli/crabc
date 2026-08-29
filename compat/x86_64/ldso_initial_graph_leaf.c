int leaf_data = 40;
int leaf_initializer_state;
static int leaf_private = 1;
static int *leaf_private_pointer = &leaf_private;
/* This dependency object must be sealed by PT_GNU_RELRO after relocation. */
static int *leaf_relro_pointer __attribute__((section(".data.rel.ro"))) = &leaf_private;

__attribute__((constructor)) static void leaf_initializer(void) {
    leaf_initializer_state = 1;
}

int leaf_value(void) {
    return leaf_data + *leaf_private_pointer - 1;
}

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

int leaf_relro_write_signal(void) {
    long child = syscall1(57, 0); /* fork */
    if (child == 0) {
        int *volatile *slot = (int *volatile *)(void *)&leaf_relro_pointer;
        *slot = &leaf_private;
        return 1;
    }
    if (child < 0) return 0;
    int status = 0;
    if (syscall4(61, child, (long)&status, 0, 0) != child) return 0; /* wait4 */
    return status & 0x7f;
}
