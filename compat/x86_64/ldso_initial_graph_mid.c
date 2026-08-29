extern int leaf_value(void);
extern int leaf_data;
extern int leaf_initializer_state;
extern int leaf_relro_write_signal(void);
int mid_initializer_state;

__attribute__((constructor)) static void mid_initializer(void) {
    mid_initializer_state = leaf_initializer_state == 1 ? 2 : -1;
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
