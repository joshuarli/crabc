extern int general_shared_tls_value(void);
extern int general_shared_tbss_value(void);
extern long general_shared_alignment(void);
extern int general_shared_mark_right_constructor(int right_tls, int right_tbss);

__thread int general_right_tls
    __attribute__((tls_model("global-dynamic"), aligned(128))) = 30;
__thread int general_right_tbss __attribute__((tls_model("global-dynamic")));

/* See the left callback: the shared stage records this branch independently,
   making dependency-first execution observable without assuming a sibling
   order for both the musl reference and private candidate. */
static void general_right_initializer(void) __attribute__((constructor(101)));

static void general_right_initializer(void) {
    (void)general_shared_mark_right_constructor(general_right_tls, general_right_tbss);
}

int general_right_initial_value(void) {
    if (general_right_tbss != 0 || general_shared_tbss_value() != 0) return -1;
    return general_right_tls + general_shared_tls_value();
}

int general_right_bump(void) {
    general_right_tls += 4;
    general_right_tbss = 5;
    return general_right_tls + general_right_tbss + general_shared_tls_value();
}

void *general_right_tls_address(void) {
    return &general_right_tls;
}

long general_right_alignment(void) {
    return ((long)&general_right_tls & 127) | general_shared_alignment();
}
