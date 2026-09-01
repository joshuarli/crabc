extern int general_left_initial_value(void);
extern int general_left_bump(void);
extern void *general_left_tls_address(void);
extern long general_left_alignment(void);
extern int general_right_initial_value(void);
extern int general_right_bump(void);
extern void *general_right_tls_address(void);
extern long general_right_alignment(void);
extern int general_shared_tls_value(void);
extern int general_shared_tbss_value(void);
extern void *general_shared_tls_address(void);
extern int general_shared_constructor_stage_value(void);

__thread int general_main_tls
    __attribute__((tls_model("global-dynamic"), aligned(512))) = 4;
__thread int general_main_tbss __attribute__((tls_model("global-dynamic")));

#if defined(CRABC_GENERAL_INITIAL_TLS_CANDIDATE)
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

static int candidate_dtv_has_one_loader_order_slot_per_tls_image(void) {
#if defined(CRABC_GENERAL_INITIAL_TLS_CANDIDATE)
    unsigned long fs_base = 0;
    unsigned long *dtv = fs_dtv();
    const struct crabc_tls_index main_tls = { 1, 0 };
    const struct crabc_tls_index left_tls = { 2, 0 };
    const struct crabc_tls_index shared_tls = { 3, 0 };
    const struct crabc_tls_index right_tls = { 4, 0 };
    const struct crabc_tls_index zero_module = { 0, 0 };
    const struct crabc_tls_index absent_module = { 5, 0 };
    const struct crabc_tls_index outside_shared = { 3, ~0UL };
    void *resolved_main = __tls_get_addr(&main_tls);
    void *resolved_left = __tls_get_addr(&left_tls);
    void *resolved_shared = __tls_get_addr(&shared_tls);
    void *resolved_right = __tls_get_addr(&right_tls);

    if (syscall2(158, 0x1003, (long)&fs_base) != 0
        || fs_base == 0
        || fs_base != fs_self()
        || dtv == 0
        || dtv[0] != 4
        || resolved_main != &general_main_tls
        || (void *)dtv[1] != resolved_main
        || resolved_left != general_left_tls_address()
        || (void *)dtv[2] != resolved_left
        || resolved_shared != general_shared_tls_address()
        || (void *)dtv[3] != resolved_shared
        || resolved_right != general_right_tls_address()
        || (void *)dtv[4] != resolved_right
        || *(int *)resolved_shared != 10
        || __tls_get_addr(&zero_module) != 0
        || __tls_get_addr(&absent_module) != 0
        || __tls_get_addr(&outside_shared) != 0) {
        return 0;
    }
#endif
    return 1;
}

int main(void) {
#if defined(CRABC_GENERAL_INITIAL_TLS_CANDIDATE)
    /* Both loader routes must run the shared dependency once before each
       branch observes its ready initial TLS. The naked pinned-musl reference
       intentionally bypasses CRT dispatch, so this is candidate-only loader
       evidence rather than an invalid constructor-order differential. */
    if (general_shared_constructor_stage_value() != 7) return 40;
#endif
    if (!candidate_dtv_has_one_loader_order_slot_per_tls_image()) return 41;
    if (general_main_tbss != 0 || general_shared_tbss_value() != 0) return 42;
    if (general_left_initial_value() != 30) return 43;
    if (general_right_initial_value() != 40) return 44;
    if (general_shared_tls_value() != 10) return 45;
    if (general_left_alignment() != 0 || general_right_alignment() != 0
        || ((long)&general_main_tls & 511) != 0) return 46;
    if (general_left_bump() != 36) return 47;
    if (general_shared_tls_value() != 11) return 48;
    if (general_right_initial_value() != 41) return 49;
    if (general_right_bump() != 50) return 50;
    general_main_tls += 5;
    general_main_tbss = 7;
    return general_main_tls + general_main_tbss == 16 ? 0 : 51;
}
