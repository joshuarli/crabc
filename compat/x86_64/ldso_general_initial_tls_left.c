extern int general_shared_tls_value(void);
extern int general_shared_tbss_value(void);
extern int general_shared_bump(void);
extern long general_shared_alignment(void);
extern int general_shared_mark_left_constructor(int left_tls, int left_tbss);

__thread int general_left_tls
    __attribute__((tls_model("global-dynamic"), aligned(64))) = 20;
__thread int general_left_tbss __attribute__((tls_model("global-dynamic")));

/*
 * This callback deliberately records its observation through the shared
 * dependency. The shared stage requires that its own callback already ran,
 * then records this branch independently so musl and the candidate may retain
 * their respective valid sibling orders.
 */
static void general_left_initializer(void) __attribute__((constructor(101)));

static void general_left_initializer(void) {
    (void)general_shared_mark_left_constructor(general_left_tls, general_left_tbss);
}

int general_left_initial_value(void) {
    if (general_left_tbss != 0 || general_shared_tbss_value() != 0) return -1;
    return general_left_tls + general_shared_tls_value();
}

int general_left_bump(void) {
    general_left_tls += 2;
    general_left_tbss = 3;
    if (general_shared_bump() != 11) return -1;
    return general_left_tls + general_left_tbss + general_shared_tls_value();
}

void *general_left_tls_address(void) {
    return &general_left_tls;
}

long general_left_alignment(void) {
    return ((long)&general_left_tls & 63) | general_shared_alignment();
}
