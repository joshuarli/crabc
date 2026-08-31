#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <string.h>

extern int mid_value(void);
extern int *mid_leaf_data_address(void);

struct visit_state {
    int mid_seen;
    int leaf_seen;
    int order;
};

static const char *base_name(const char *path) {
    const char *name = path;
    for (const char *cursor = path; *cursor != '\0'; ++cursor) {
        if (*cursor == '/') name = cursor + 1;
    }
    return name;
}

static int visit(struct dl_phdr_info *info, size_t size, void *opaque) {
    struct visit_state *state = opaque;
    if (size < offsetof(struct dl_phdr_info, dlpi_phnum) + sizeof(info->dlpi_phnum)
        || info->dlpi_phdr == 0 || info->dlpi_phnum == 0) {
        return 80;
    }
    const char *name = base_name(info->dlpi_name);
    if (strcmp(name, "libmid-introspection.so") == 0) {
        if (state->mid_seen || state->leaf_seen) return 81;
        state->mid_seen = 1;
        state->order = state->order * 10 + 1;
    } else if (strcmp(name, "libleaf-introspection.so") == 0) {
        if (!state->mid_seen || state->leaf_seen) return 82;
        state->leaf_seen = 1;
        state->order = state->order * 10 + 2;
    }
    return 0;
}

int main(void) {
    struct visit_state state = {0};
    if (mid_value() != 42) return 83;
    if (dl_iterate_phdr(visit, &state) != 0
        || !state.mid_seen || !state.leaf_seen || state.order != 12) {
        return 84;
    }

    Dl_info address;
    if (dladdr((const void *)&mid_value, &address) == 0
        || strcmp(base_name(address.dli_fname), "libmid-introspection.so") != 0
        || strcmp(address.dli_sname, "mid_value") != 0
        || address.dli_saddr != (void *)&mid_value) {
        return 85;
    }
    int *leaf_data = mid_leaf_data_address();
    if (dladdr((const void *)leaf_data, &address) == 0
        || strcmp(base_name(address.dli_fname), "libleaf-introspection.so") != 0
        || strcmp(address.dli_sname, "leaf_data") != 0
        || address.dli_saddr != (void *)leaf_data) {
        return 86;
    }

    void *handle = dlopen("libmid-introspection.so", RTLD_NOW | RTLD_LOCAL);
    struct link_map *map = 0;
    if (handle == 0 || dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == 0
        || strcmp(base_name(map->l_name), "libmid-introspection.so") != 0
        || map->l_ld == 0 || dlclose(handle) != 0) {
        return 87;
    }
    return 0;
}
