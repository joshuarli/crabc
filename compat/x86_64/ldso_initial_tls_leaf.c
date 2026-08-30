/*
 * Fixed-graph initial TLS dependency for the private x86 loader evidence.
 *
 * The two models deliberately make the loader materialize both the
 * module/offset `__tls_get_addr` route.  The 4096-byte alignment is part of
 * the behavioral contract: a merely contiguous, unaligned copy is not an x86
 * Variant-II initial TLS implementation.  Initial-exec/TPOFF and TLSDESC
 * remain later loader obligations, so this source must stay GNU-Dynamic.
 */
__thread int leaf_general_tls __attribute__((tls_model("global-dynamic"))) = 40;
__thread int leaf_aligned_tls __attribute__((tls_model("global-dynamic"), aligned(4096))) = 2;
__thread int leaf_zero_tls __attribute__((tls_model("global-dynamic")));
/* Keep the fixed graph's independently proved packed-RELR path live too. */
static int leaf_relative_value = 1;
static int *volatile leaf_relative_pointer = &leaf_relative_value;
static volatile int leaf_non_tls_bss;

int leaf_tls_value(void) {
    return leaf_general_tls + leaf_aligned_tls + *leaf_relative_pointer - 1 + leaf_non_tls_bss;
}

int leaf_tls_bump(void) {
    leaf_general_tls += 1;
    leaf_aligned_tls += 2;
    leaf_zero_tls = 5;
    return leaf_tls_value();
}

long leaf_aligned_tls_alignment(void) {
    return (long)&leaf_aligned_tls & 4095;
}

int leaf_zero_tls_value(void) {
    return leaf_zero_tls;
}
