extern int leaf_data;

int bounded_plugin_legacy_init_runs;
int bounded_plugin_constructor_runs;
int bounded_plugin_constructor_value;
int bounded_plugin_initializer_order;
#ifdef CRABC_BOUNDED_PLUGIN_INVALID_INIT
int bounded_plugin_invalid_init;
#endif

/*
 * The runner binds this exact exported function through DT_INIT.  Keeping the
 * marker separate from the init-array entry makes the legacy-init-before-array
 * order observable without involving any ambient C runtime state.
 */
void bounded_plugin_legacy_initialize(void) {
    ++bounded_plugin_legacy_init_runs;
    if (bounded_plugin_initializer_order != 0) {
        bounded_plugin_initializer_order = -1;
        return;
    }
    bounded_plugin_initializer_order = 1;
    bounded_plugin_constructor_value = leaf_data + 3;
}

__attribute__((constructor)) static void bounded_plugin_initialize(void) {
    ++bounded_plugin_constructor_runs;
    if (bounded_plugin_initializer_order != 1) {
        bounded_plugin_initializer_order = -2;
        return;
    }
    bounded_plugin_initializer_order = 2;
    bounded_plugin_constructor_value += 34;
}

int bounded_plugin_value(void) {
    return bounded_plugin_constructor_value;
}
