extern __thread int leaf_general_tls;
extern int leaf_tls_value(void);
extern int leaf_tls_bump(void);
extern long leaf_aligned_tls_alignment(void);
extern int leaf_zero_tls_value(void);

__thread int mid_general_tls __attribute__((tls_model("global-dynamic"))) = 7;

int mid_tls_value(void) {
    return mid_general_tls + leaf_general_tls + leaf_tls_value();
}

int mid_tls_bump(void) {
    mid_general_tls += 3;
    (void)leaf_tls_bump();
    return mid_tls_value();
}

long mid_leaf_tls_alignment(void) {
    return leaf_aligned_tls_alignment();
}

int mid_leaf_zero_tls_value(void) {
    return leaf_zero_tls_value();
}
