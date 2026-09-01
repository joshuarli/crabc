/*
 * Shared TLS leaf for the private general initial-TLS graph. Both branch DSOs
 * carry a DT_NEEDED edge to this one inode, so this image must receive one
 * loader-order module ID and one DTV slot rather than one per pathname edge.
 */
__thread int general_shared_tls
    __attribute__((tls_model("global-dynamic"), aligned(4096))) = 10;
__thread int general_shared_tbss __attribute__((tls_model("global-dynamic")));

/*
 * The general initial-TLS runner uses this one process-global stage to make
 * the dependency-only DT_INIT_ARRAY contract observable from `main`.
 *
 * The shared object occurs both as a direct main dependency and below each
 * branch, so a second callback is a graph-identity error rather than a second
 * valid initialization. Its callback must therefore see its initialized
 * template and zero-filled tbss exactly once before either branch can record
 * its own initialized TLS observation. This is single-threaded loader-startup
 * evidence, not a synchronization primitive.
 */
static volatile int general_shared_constructor_stage;

static void general_shared_initializer(void) __attribute__((constructor(101)));

static void general_shared_initializer(void) {
    if (general_shared_constructor_stage != 0 || general_shared_tls != 10
        || general_shared_tbss != 0) {
        general_shared_constructor_stage = -1;
        return;
    }
    general_shared_constructor_stage = 1;
}

/*
 * These two calls are made by the left and right dependency constructors.
 * They prove shared runs before both branches while retaining a distinct bit
 * for each branch and rejecting any repeated callback. Pinned musl and the
 * candidate need not use the same valid sibling order; the separate non-TLS
 * candidate gate ratchets its declared-edge postorder.
 */
int general_shared_mark_left_constructor(int left_tls, int left_tbss) {
    if ((general_shared_constructor_stage & 1) == 0
        || (general_shared_constructor_stage & 2) != 0
        || general_shared_tls != 10
        || general_shared_tbss != 0 || left_tls != 20 || left_tbss != 0) {
        general_shared_constructor_stage = -1;
        return -1;
    }
    general_shared_constructor_stage |= 2;
    return 0;
}

int general_shared_mark_right_constructor(int right_tls, int right_tbss) {
    if ((general_shared_constructor_stage & 1) == 0
        || (general_shared_constructor_stage & 4) != 0
        || general_shared_tls != 10
        || general_shared_tbss != 0 || right_tls != 30 || right_tbss != 0) {
        general_shared_constructor_stage = -1;
        return -1;
    }
    general_shared_constructor_stage |= 4;
    return 0;
}

int general_shared_constructor_stage_value(void) {
    return general_shared_constructor_stage;
}

/*
 * Retain an ordinary readable PT_LOAD BSS tail in this otherwise tiny DSO.
 * The negative ELF mutation repoints PT_TLS at its first byte to prove the
 * loader refuses an initialized TLS prefix that crosses the file-backed load
 * boundary; `.tbss` alone does not extend a PT_LOAD's p_memsz on x86-64.
 */
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
