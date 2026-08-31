/* A DSO may not consume the interpreter's private main-only record. */
extern const unsigned char __crabc_x86_64_fixed_graph_dlfcn_v1[64]
    __attribute__((weak));

const void *mid_dlfcn_record_import(void) {
    return __crabc_x86_64_fixed_graph_dlfcn_v1;
}
