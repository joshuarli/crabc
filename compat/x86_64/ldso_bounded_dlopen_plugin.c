extern int leaf_data;

int bounded_plugin_constructor_runs;
int bounded_plugin_constructor_value;

__attribute__((constructor)) static void bounded_plugin_initialize(void) {
    ++bounded_plugin_constructor_runs;
    bounded_plugin_constructor_value = leaf_data + 3;
}

int bounded_plugin_value(void) {
    return bounded_plugin_constructor_value + 34;
}
