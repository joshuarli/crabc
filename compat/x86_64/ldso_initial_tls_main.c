extern int mid_tls_value(void);
extern int mid_tls_bump(void);
extern long mid_leaf_tls_alignment(void);
extern int mid_leaf_zero_tls_value(void);
#if defined(CRABC_INITIAL_EXEC_TLS)
extern int mid_leaf_initial_exec_tls_value(void);
extern int mid_leaf_initial_exec_tls_bump(void);
#endif

#if defined(CRABC_CANDIDATE_TLS_LAYOUT)
struct crabc_tls_index {
    unsigned long module;
    unsigned long offset;
};

extern void *__tls_get_addr(const struct crabc_tls_index *index);
#endif

static long syscall2(long number, long one, long two) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(one), "S"(two) : "rcx", "r11", "memory");
    return result;
}

static unsigned long fs_self(void) {
    unsigned long value;
    __asm__ volatile("movq %%fs:0, %0" : "=r"(value));
    return value;
}

static unsigned long *fs_dtv(void) {
    unsigned long *value;
    __asm__ volatile("movq %%fs:8, %0" : "=r"(value));
    return value;
}

static int initial_tls_thread_pointer_is_consistent(void) {
#if defined(CRABC_CANDIDATE_TLS_LAYOUT)
    unsigned long fs_base = 0;
    unsigned long *dtv = fs_dtv();
    if (syscall2(158, 0x1003, (long)&fs_base) != 0
        || fs_base == 0
        || fs_base != fs_self()
        || dtv == 0
        || dtv[0] != 2) {
        return 0;
    }
#endif
    return 1;
}

static int candidate_tls_resolver_is_bounded(void) {
#if defined(CRABC_CANDIDATE_TLS_LAYOUT)
    const struct crabc_tls_index leaf_general = { 2, 0 };
    const struct crabc_tls_index absent_module = { 3, 0 };
    const struct crabc_tls_index outside_leaf = { 2, ~0UL };
    int *value = (int *)__tls_get_addr(&leaf_general);
    if (value == 0 || *value != 40
        || __tls_get_addr(&absent_module) != 0
        || __tls_get_addr(&outside_leaf) != 0) {
        return 0;
    }
#endif
    return 1;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (!initial_tls_thread_pointer_is_consistent()) return 41;
    if (!candidate_tls_resolver_is_bounded()) return 47;
    if (mid_tls_value() != 89) return 42;
    if (mid_leaf_tls_alignment() != 0) return 43;
    if (mid_leaf_zero_tls_value() != 0) return 44;
    if (mid_tls_bump() != 96) return 45;
#if defined(CRABC_INITIAL_EXEC_TLS)
    if (mid_leaf_initial_exec_tls_value() != 31) return 48;
    if (mid_leaf_initial_exec_tls_bump() != 37) return 49;
#endif
    return mid_leaf_zero_tls_value() == 5 ? 0 : 46;
}
