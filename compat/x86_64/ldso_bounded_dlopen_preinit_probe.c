#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

extern int mid_value(void);

struct graph_observation {
    int visits;
    int preinit_plugin_seen;
    unsigned long long additions;
};

static int contains(const char *text, const char *needle) {
    if (text == NULL) return 0;
    for (size_t start = 0; text[start] != '\0'; ++start) {
        size_t offset = 0;
        while (needle[offset] != '\0' && text[start + offset] != '\0'
               && text[start + offset] == needle[offset]) {
            ++offset;
        }
        if (needle[offset] == '\0') return 1;
    }
    return 0;
}

static int observe_graph(struct dl_phdr_info *information, size_t size, void *opaque) {
    struct graph_observation *observation = opaque;
    if (size != sizeof(*information) || information->dlpi_phdr == NULL
        || information->dlpi_phnum == 0) return 90;
    ++observation->visits;
    if (contains(information->dlpi_name, "libbounded-preinit.so")) {
        observation->preinit_plugin_seen = 1;
    }
    observation->additions = information->dlpi_adds;
    return 0;
}

int main(void) {
    if (mid_value() != 42) return 40;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    struct graph_observation before = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &before) != 0 || before.visits != 3
        || before.preinit_plugin_seen || before.additions != 0) return 41;
    if (dlopen("libbounded-preinit-malformed.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 42;
    struct graph_observation after_malformed = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &after_malformed) != 0
        || after_malformed.visits != 3 || after_malformed.preinit_plugin_seen
        || after_malformed.additions != 0) return 43;
#endif

    void *handle = dlopen("libbounded-preinit.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 44;
    int *runs = dlsym(handle, "bounded_preinit_array_runs");
    int (*value)(void) = (int (*)(void))dlsym(handle, "bounded_preinit_value");
    if (runs == NULL || value == NULL || *runs != 0 || value() != 83) return 45;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    struct graph_observation after = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &after) != 0 || after.visits != 4
        || !after.preinit_plugin_seen || after.additions != 1) return 46;
#endif

    return dlclose(handle) == 0 ? 0 : 47;
}
