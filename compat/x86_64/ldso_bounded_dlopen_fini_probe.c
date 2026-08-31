#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

extern int mid_value(void);

/*
 * This is deliberately a separate no-NODELETE route.  It proves the last
 * ordinary explicit close leaves a legacy DT_FINI hook inert, rather than
 * attributing the result to the adjacent NODELETE residency evidence.
 */
int main(void) {
    if (mid_value() != 42) return 100;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (dlopen("libbounded-fini-malformed.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 101;
#endif

    void *first = dlopen("libbounded-fini-plugin.so", RTLD_NOW | RTLD_LOCAL);
    if (first == NULL) return 102;
    int (*value)(void) = (int (*)(void))dlsym(first, "bounded_plugin_value");
    int *legacy_init_runs = dlsym(first, "bounded_plugin_legacy_init_runs");
    int *legacy_fini_runs = dlsym(first, "bounded_plugin_legacy_fini_runs");
    int *constructor_runs = dlsym(first, "bounded_plugin_constructor_runs");
    int *initializer_order = dlsym(first, "bounded_plugin_initializer_order");
    if (value == NULL || legacy_init_runs == NULL || legacy_fini_runs == NULL
        || constructor_runs == NULL || initializer_order == NULL || value() != 77
        || *legacy_init_runs != 1 || *legacy_fini_runs != 0
        || *constructor_runs != 1 || *initializer_order != 2) return 103;
    if (dlclose(first) != 0) return 104;

    void *second = dlopen("libbounded-fini-plugin.so", RTLD_LAZY | RTLD_LOCAL);
    if (second == NULL) return 105;
    int *second_legacy_fini_runs =
        dlsym(second, "bounded_plugin_legacy_fini_runs");
    if (dlsym(second, "bounded_plugin_value") != (void *)value
        || second_legacy_fini_runs != legacy_fini_runs || *second_legacy_fini_runs != 0
        || *legacy_init_runs != 1 || *constructor_runs != 1 || *initializer_order != 2)
        return 106;
    if (dlclose(second) != 0) return 107;

    void *third = dlopen("libbounded-fini-plugin.so", RTLD_NOW | RTLD_LOCAL);
    if (third == NULL) return 108;
    int *third_legacy_fini_runs = dlsym(third, "bounded_plugin_legacy_fini_runs");
    if (dlsym(third, "bounded_plugin_value") != (void *)value
        || third_legacy_fini_runs != legacy_fini_runs || *third_legacy_fini_runs != 0
        || *legacy_init_runs != 1 || *constructor_runs != 1 || *initializer_order != 2)
        return 109;
    if (dlclose(third) != 0) return 110;
    return 0;
}
