extern int leaf_data;

int bounded_plugin_legacy_init_runs;
int bounded_plugin_legacy_fini_runs;
int bounded_plugin_constructor_runs;
int bounded_plugin_constructor_value;
int bounded_plugin_initializer_order;
#ifdef CRABC_BOUNDED_PLUGIN_INVALID_INIT
int bounded_plugin_invalid_init;
#endif
#ifdef CRABC_BOUNDED_PLUGIN_INVALID_FINI
int bounded_plugin_invalid_fini;
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

/*
 * The Fini-focused runner binds this exact function through DT_FINI.  Pinned
 * musl retains a legacy DT_FINI tag but does not dispatch it on dlclose; the
 * exported counter makes that inert-tag rule observable without selecting a
 * DT_FINI_ARRAY or an unload implementation.
 */
void bounded_plugin_legacy_finalize(void) {
    ++bounded_plugin_legacy_fini_runs;
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
