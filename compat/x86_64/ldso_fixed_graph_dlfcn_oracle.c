#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <string.h>

extern int mid_value(void);
extern int *mid_leaf_data_address(void);

struct observed_graph {
    int main_seen;
    int mid_seen;
    int leaf_seen;
};

static int observe_image(struct dl_phdr_info *information, size_t size, void *opaque) {
    struct observed_graph *observed = opaque;
    if (size < offsetof(struct dl_phdr_info, dlpi_phnum) + sizeof(information->dlpi_phnum)
        || information->dlpi_phdr == NULL || information->dlpi_phnum == 0) {
        return 1;
    }
    if (information->dlpi_name == NULL || information->dlpi_name[0] == '\0') {
        observed->main_seen = 1;
    } else if (strstr(information->dlpi_name, "libmid-dlfcn.so") != NULL) {
        observed->mid_seen = 1;
    } else if (strstr(information->dlpi_name, "libleaf-dlfcn.so") != NULL) {
        observed->leaf_seen = 1;
    }
    return 0;
}

int main(void) {
    void *main_handle = dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
    void *mid_one = dlopen("libmid-dlfcn.so", RTLD_NOW | RTLD_LOCAL);
    void *mid_two = dlopen("libmid-dlfcn.so", RTLD_LAZY | RTLD_LOCAL);
    void *leaf = dlopen("libleaf-dlfcn.so", RTLD_NOW | RTLD_LOCAL);
    if (main_handle == NULL || mid_one == NULL || mid_two == NULL || leaf == NULL
        || mid_one != mid_two) {
        return 60;
    }

    dlerror();
    void *mid_symbol = dlsym(mid_one, "mid_value");
    if (dlerror() != NULL || mid_symbol != (void *)&mid_value
        || ((int (*)(void))mid_symbol)() != 42) {
        return 61;
    }
    dlerror();
    void *main_symbol = dlsym(main_handle, "mid_value");
    if (dlerror() != NULL || main_symbol != mid_symbol) return 62;

    dlerror();
    void *leaf_symbol = dlsym(mid_one, "leaf_data");
    if (dlerror() != NULL || leaf_symbol != (void *)mid_leaf_data_address()) return 63;
    dlerror();
    if (dlsym(leaf, "mid_value") != NULL || dlerror() == NULL) return 64;

    Dl_info address;
    if (dladdr(mid_symbol, &address) == 0 || address.dli_fbase == NULL
        || address.dli_saddr != mid_symbol || address.dli_sname == NULL
        || strcmp(address.dli_sname, "mid_value") != 0) {
        return 65;
    }
    struct link_map *link_map = NULL;
    if (dlinfo(mid_one, RTLD_DI_LINKMAP, &link_map) != 0 || link_map == NULL
        || link_map->l_addr != (ElfW(Addr))address.dli_fbase || link_map->l_ld == NULL) {
        return 66;
    }

    struct observed_graph observed = {0, 0, 0};
    if (dl_iterate_phdr(observe_image, &observed) != 0
        || !observed.main_seen || !observed.mid_seen || !observed.leaf_seen) {
        return 67;
    }

    dlerror();
    if (dlsym(mid_one, "crabc_missing_fixed_graph_symbol") != NULL || dlerror() == NULL) {
        return 68;
    }
    dlerror();
    if (dlopen("libcrabc-not-loaded.so", RTLD_NOW | RTLD_LOCAL) != NULL || dlerror() == NULL) {
        return 69;
    }

    if (dlclose(mid_one) != 0 || ((int (*)(void))dlsym(mid_two, "mid_value"))() != 42
        || dlclose(mid_two) != 0 || dlclose(leaf) != 0 || dlclose(main_handle) != 0) {
        return 70;
    }
    return 0;
}
