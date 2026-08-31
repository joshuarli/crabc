/*
 * The fixed interpreter admits exactly main -> mid -> leaf.  Keep the probe's
 * direct imports in the middle object so the finite data address still belongs
 * to the leaf while the main has only its one normal DT_NEEDED edge.
 */

extern const unsigned char *dladdr_leaf_data_address(void);
extern const unsigned char *dladdr_leaf_interior_address(void);
extern const unsigned char *dladdr_leaf_gap_address(void);

const unsigned char *dladdr_bounded_data_address(void) {
    return dladdr_leaf_data_address();
}

const unsigned char *dladdr_bounded_interior_address(void) {
    return dladdr_leaf_interior_address();
}

const unsigned char *dladdr_bounded_gap_address(void) {
    return dladdr_leaf_gap_address();
}
