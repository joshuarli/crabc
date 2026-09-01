/*
 * One freestanding consumer of the private x86 loader/libc TLS RuntimeV1
 * handoff.  This is intentionally not an installed C ABI.  The Rust
 * consumer must validate the loader-owned record before it observes the
 * initial graph's GNU-Dynamic TLS values below.
 */

extern int __crabc_x86_loader_tls_runtime_v1_attach(void);
extern int mid_tls_value(void);
extern int mid_tls_bump(void);
extern long mid_leaf_tls_alignment(void);
extern int mid_leaf_zero_tls_value(void);

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int handoff = __crabc_x86_loader_tls_runtime_v1_attach();
#if defined(CRABC_RUNTIME_V1_REJECT)
    /*
     * Metadata-only negatives retain live initial-TLS coordinates, so a
     * successful return proves one required descriptor check was omitted.
     * The separate poisoned-DTV negative has valid metadata but an unusable
     * DTV pointer and therefore proves the pointer gate comes before a DTV
     * read.
     */
    return handoff == 0 ? 71 : 0;
#else
    if (handoff != 0) return 70;
    if (mid_tls_value() != 89) return 72;
    if (mid_leaf_tls_alignment() != 0) return 73;
    if (mid_leaf_zero_tls_value() != 0) return 74;
    if (mid_tls_bump() != 96) return 75;
    return mid_leaf_zero_tls_value() == 5 ? 0 : 76;
#endif
}
