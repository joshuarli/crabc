/*
 * Freestanding consumer for the private x86 general-initial TLS RuntimeV1
 * handoff. This remains a no-CRT fixture: dependency constructors establish
 * their shared -> left -> right order before main, then this program verifies
 * the libc observer sees exactly the loader-owned initial DTV geometry.
 */

extern int __crabc_x86_loader_tls_runtime_v1_attach(void);
extern int general_left_initial_value(void);
extern int general_left_bump(void);
extern void *general_left_tls_address(void);
extern int general_right_initial_value(void);
extern void *general_right_tls_address(void);
extern int general_shared_constructor_stage_value(void);
extern int general_shared_tbss_value(void);
extern int general_shared_tls_value(void);
extern void *general_shared_tls_address(void);

/* Exported only to this fixture's shared dependency. The loader's ordinary
   symbol resolver reaches this main-image function, while the private record
   address itself still uses the stricter weak-data exception in Rust. */
int general_runtime_v1_constructor_attach(void) {
    return __crabc_x86_loader_tls_runtime_v1_attach();
}

__thread int general_runtime_v1_main_tls
    __attribute__((tls_model("global-dynamic"), aligned(512))) = 4;
__thread int general_runtime_v1_main_tbss
    __attribute__((tls_model("global-dynamic")));

#if !defined(CRABC_GENERAL_RUNTIME_V1_REJECT)
struct crabc_tls_index {
    unsigned long module;
    unsigned long offset;
};

extern void *__tls_get_addr(const struct crabc_tls_index *index);

static long syscall2(long number, long one, long two) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(one), "S"(two)
                     : "rcx", "r11", "memory");
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

static int exact_general_initial_dtv(void) {
    unsigned long fs_base = 0;
    unsigned long *dtv = fs_dtv();
    const struct crabc_tls_index main_tls = { 1, 0 };
    const struct crabc_tls_index left_tls = { 2, 0 };
    const struct crabc_tls_index shared_tls = { 3, 0 };
    const struct crabc_tls_index right_tls = { 4, 0 };
    const struct crabc_tls_index absent_tls = { 5, 0 };
    void *resolved_main = __tls_get_addr(&main_tls);
    void *resolved_left = __tls_get_addr(&left_tls);
    void *resolved_shared = __tls_get_addr(&shared_tls);
    void *resolved_right = __tls_get_addr(&right_tls);

    if (syscall2(158, 0x1003, (long)&fs_base) != 0
        || fs_base == 0
        || fs_base != fs_self()
        || dtv == 0
        || dtv[0] != 4
        || resolved_main != &general_runtime_v1_main_tls
        || (void *)dtv[1] != resolved_main
        || resolved_left != general_left_tls_address()
        || (void *)dtv[2] != resolved_left
        || resolved_shared != general_shared_tls_address()
        || (void *)dtv[3] != resolved_shared
        || resolved_right != general_right_tls_address()
        || (void *)dtv[4] != resolved_right
        || __tls_get_addr(&absent_tls) != 0) {
        return 0;
    }
    return 1;
}
#endif

int main(void) {
    int handoff = general_runtime_v1_constructor_attach();

#if defined(CRABC_GENERAL_RUNTIME_V1_REJECT)
    /*
     * Each malformed descriptor retains the actual general initial graph.
     * A success here would therefore isolate an omitted libc metadata or
     * pointer check rather than being hidden by an unrelated graph failure.
     */
    return handoff == 0 ? 71 : 0;
#else
    if (handoff != 0) return 70;
    if (!exact_general_initial_dtv()) return 72;
    if (general_shared_constructor_stage_value() != 7) return 73;
    if (general_runtime_v1_main_tbss != 0 || general_shared_tbss_value() != 0)
        return 74;
    if (general_left_initial_value() != 30) return 75;
    if (general_right_initial_value() != 40) return 76;
    if (general_shared_tls_value() != 10) return 77;
    if (general_left_bump() != 36) return 78;
    general_runtime_v1_main_tls += 5;
    general_runtime_v1_main_tbss = 7;
    return general_runtime_v1_main_tls + general_runtime_v1_main_tbss == 16 ? 0 : 79;
#endif
}
