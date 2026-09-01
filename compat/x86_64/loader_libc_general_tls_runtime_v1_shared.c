/*
 * General-TLS RuntimeV1 shared leaf. Its first dependency callback calls back
 * into the main image's freestanding libc observer, making READY-before-
 * callback ordering observable without granting a DSO the private descriptor
 * symbol itself. The loader continues to reject descriptor imports outside
 * the main image.
 */

extern int general_runtime_v1_constructor_attach(void);

__thread int general_shared_tls
    __attribute__((tls_model("global-dynamic"), aligned(4096))) = 10;
__thread int general_shared_tbss __attribute__((tls_model("global-dynamic")));

static volatile int general_shared_constructor_stage;

static void general_shared_initializer(void) __attribute__((constructor(101)));

static void general_shared_initializer(void) {
    if (general_runtime_v1_constructor_attach() != 0
        || general_shared_constructor_stage != 0 || general_shared_tls != 10
        || general_shared_tbss != 0) {
        general_shared_constructor_stage = -1;
        return;
    }
    general_shared_constructor_stage = 1;
}

int general_shared_mark_left_constructor(int left_tls, int left_tbss) {
    if ((general_shared_constructor_stage & 1) == 0
        || (general_shared_constructor_stage & 2) != 0
        || general_shared_tls != 10 || general_shared_tbss != 0
        || left_tls != 20 || left_tbss != 0) {
        general_shared_constructor_stage = -1;
        return -1;
    }
    general_shared_constructor_stage |= 2;
    return 0;
}

int general_shared_mark_right_constructor(int right_tls, int right_tbss) {
    if ((general_shared_constructor_stage & 1) == 0
        || (general_shared_constructor_stage & 4) != 0
        || general_shared_tls != 10 || general_shared_tbss != 0
        || right_tls != 30 || right_tbss != 0) {
        general_shared_constructor_stage = -1;
        return -1;
    }
    general_shared_constructor_stage |= 4;
    return 0;
}

int general_shared_constructor_stage_value(void) {
    return general_shared_constructor_stage;
}

char general_shared_non_tls_bss[16];

int general_shared_tls_value(void) {
    return general_shared_tls;
}

int general_shared_tbss_value(void) {
    return general_shared_tbss;
}

int general_shared_bump(void) {
    general_shared_tls += 1;
    return general_shared_tls;
}

void *general_shared_tls_address(void) {
    return &general_shared_tls;
}

long general_shared_alignment(void) {
    return (long)&general_shared_tls & 4095;
}
