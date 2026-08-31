extern int leaf_value(void);
extern int leaf_data;
extern int leaf_initializer_state;
extern int leaf_relro_write_signal(void);
int mid_initializer_state;

#if defined(CRABC_OWNED_CRT_HANDOFF)
extern void crabc_owned_crt_record_dependency(char);
#endif

__attribute__((constructor)) static void mid_initializer(void) {
    mid_initializer_state = leaf_initializer_state == 1 ? 2 : -1;
#if defined(CRABC_OWNED_CRT_HANDOFF)
    crabc_owned_crt_record_dependency('d');
#endif
}

int mid_value(void) {
    return leaf_value() + leaf_data - 40 + 2;
}

int mid_initializers_ran(void) {
    return mid_initializer_state == 2;
}

int mid_leaf_relro_write_signal(void) {
    return leaf_relro_write_signal();
}

#if defined(CRABC_FIXED_GRAPH_INTROSPECTION) || defined(CRABC_FIXED_GRAPH_DLFCN)
int *mid_leaf_data_address(void) {
    return &leaf_data;
}
#endif
