#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

#ifndef CRABC_BOUNDED_DLFCN_FREESTANDING
#include <pthread.h>
#endif

extern int mid_value(void);

_Static_assert(RTLD_NODELETE == 4096, "RTLD_NODELETE x86 ABI");

struct graph_observation {
    int visits;
    int plugin_seen;
    int nonzero_additions;
    unsigned long long additions;
};

static int contains(const char *text, const char *needle) {
    if (text == NULL) return 0;
    for (size_t start = 0; text[start] != '\0'; ++start) {
        size_t offset = 0;
        while (needle[offset] != '\0' && text[start + offset] == needle[offset]) ++offset;
        if (needle[offset] == '\0') return 1;
    }
    return 0;
}

static int observe_graph(struct dl_phdr_info *information, size_t size, void *opaque) {
    struct graph_observation *observation = opaque;
    if (size != sizeof(*information) || information->dlpi_phdr == NULL
        || information->dlpi_phnum == 0) return 90;
    ++observation->visits;
    if (contains(information->dlpi_name, "libbounded-plugin.so")) {
        observation->plugin_seen = 1;
    }
    if (information->dlpi_adds != 0) observation->nonzero_additions = 1;
    observation->additions = information->dlpi_adds;
    return 0;
}

struct open_worker {
    volatile int go;
    volatile int done;
    void *handle;
};

static void *open_worker_main(void *opaque) {
    struct open_worker *worker = opaque;
    while (!__atomic_load_n(&worker->go, __ATOMIC_ACQUIRE)) { }
    worker->handle = dlopen(
        "libbounded-plugin.so", RTLD_NOW | RTLD_NODELETE | RTLD_LOCAL);
    __atomic_store_n(&worker->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
extern long crabc_spawn_dlfcn_thread(void *(*)(void *), void *, void *, int *);
static unsigned char worker_stacks[2][32768] __attribute__((aligned(16)));

static int run_concurrent_open(struct open_worker workers[2]) {
    int child_tids[2] = {0, 0};
    for (int index = 0; index < 2; ++index) {
        void *top = worker_stacks[index] + sizeof(worker_stacks[index]);
        if (crabc_spawn_dlfcn_thread(open_worker_main, &workers[index], top,
                                     &child_tids[index]) <= 0) return 0;
    }
    __atomic_store_n(&workers[0].go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&workers[1].go, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&workers[0].done, __ATOMIC_ACQUIRE)
           || !__atomic_load_n(&workers[1].done, __ATOMIC_ACQUIRE)) { }
    while (__atomic_load_n(&child_tids[0], __ATOMIC_ACQUIRE) != 0
           || __atomic_load_n(&child_tids[1], __ATOMIC_ACQUIRE) != 0) { }
    return 1;
}
#else
static int run_concurrent_open(struct open_worker workers[2]) {
    pthread_t threads[2];
    if (pthread_create(&threads[0], NULL, open_worker_main, &workers[0]) != 0
        || pthread_create(&threads[1], NULL, open_worker_main, &workers[1]) != 0) return 0;
    __atomic_store_n(&workers[0].go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&workers[1].go, 1, __ATOMIC_RELEASE);
    return pthread_join(threads[0], NULL) == 0 && pthread_join(threads[1], NULL) == 0;
}
#endif

int main(void) {
    if (mid_value() != 42) return 40;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    struct graph_observation before = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &before) != 0 || before.visits != 3
        || before.plugin_seen || before.nonzero_additions) return 41;
    if (dlopen("libbounded-tls.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 42;
    if (dlopen("libbounded-unretained.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 43;
    if (dlopen("libbounded-init-malformed.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 44;
    struct graph_observation after_malformed = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &after_malformed) != 0
        || after_malformed.visits != 3 || after_malformed.plugin_seen
        || after_malformed.nonzero_additions) return 45;
    if (dlopen("./libbounded-plugin.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL) return 45;
#endif
    if (dlopen("libbounded-plugin.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 46;
#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (dlopen("libbounded-plugin.so",
               RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE | RTLD_LOCAL) != NULL) return 47;
    char *noload_nodelete_error = dlerror();
    if (!contains(noload_nodelete_error, "RTLD_NOLOAD object is not loaded")
        || dlerror() != NULL) return 47;
    struct graph_observation after_noload = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &after_noload) != 0
        || after_noload.visits != 3 || after_noload.plugin_seen
        || after_noload.nonzero_additions) return 48;
    if (dlopen(NULL, RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 49;
    /* The static bridge's bare NULL/NOLOAD observation stays disabled here. */
    if (dlopen(NULL, RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 82;
    if (dlopen("libmid-bounded-dlopen.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 49;
    if (dlopen("libleaf-bounded-dlopen.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 49;
    if (dlopen(NULL, RTLD_NOW | RTLD_NODELETE | RTLD_LOCAL) != NULL) return 50;
    char *null_nodelete_error = dlerror();
    if (!contains(null_nodelete_error, "RTLD_NODELETE is limited to the runtime object")
        || dlerror() != NULL) return 50;
    if (dlopen("libmid-bounded-dlopen.so", RTLD_NOW | RTLD_NODELETE | RTLD_LOCAL) != NULL)
        return 51;
    char *initial_nodelete_error = dlerror();
    if (!contains(initial_nodelete_error, "RTLD_NODELETE is limited to the runtime object")
        || dlerror() != NULL) return 51;
#endif

    struct open_worker workers[2] = {{0, 0, NULL}, {0, 0, NULL}};
    if (!run_concurrent_open(workers) || workers[0].handle == NULL
        || workers[0].handle != workers[1].handle) return 52;
    void *handle = workers[0].handle;
    struct graph_observation before_noload = {0, 0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &before_noload) != 0
        || !before_noload.plugin_seen) return 65;
    void *noload_handle = dlopen("libbounded-plugin.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    if (noload_handle != handle) return 53;
    void *lazy_noload_handle =
        dlopen("libbounded-plugin.so", RTLD_LAZY | RTLD_NOLOAD | RTLD_LOCAL);
    if (lazy_noload_handle != handle) return 67;
    void *nodelete_noload_handle = dlopen(
        "libbounded-plugin.so", RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE | RTLD_LOCAL);
    if (nodelete_noload_handle != handle) return 68;
    void *lazy_nodelete_noload_handle = dlopen(
        "libbounded-plugin.so", RTLD_LAZY | RTLD_NOLOAD | RTLD_NODELETE | RTLD_LOCAL);
    if (lazy_nodelete_noload_handle != handle) return 69;
    int (*plugin_value)(void) = (int (*)(void))dlsym(handle, "bounded_plugin_value");
    int *legacy_init_runs = dlsym(handle, "bounded_plugin_legacy_init_runs");
    int *constructor_runs = dlsym(handle, "bounded_plugin_constructor_runs");
    int *dependency_data = dlsym(handle, "leaf_data");
    int *initializer_order = dlsym(handle, "bounded_plugin_initializer_order");
    if (plugin_value == NULL || legacy_init_runs == NULL || constructor_runs == NULL
        || dependency_data == NULL || initializer_order == NULL || plugin_value() != 77
        || *legacy_init_runs != 1 || *constructor_runs != 1 || *initializer_order != 2
        || *dependency_data != 40) return 54;

    Dl_info address = {0};
    if (dladdr((const void *)plugin_value, &address) != 1
        || !contains(address.dli_fname, "libbounded-plugin.so")
        || !contains(address.dli_sname, "bounded_plugin_value")
        || address.dli_saddr != (void *)plugin_value) return 55;
    struct link_map *map = NULL;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == NULL
        || !contains(map->l_name, "libbounded-plugin.so") || map->l_ld == NULL) return 56;

    struct graph_observation after = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &after) != 0 || !after.plugin_seen) return 57;
#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    /* The bounded copied snapshot records graph mutations, not references. */
    if (after.visits != before_noload.visits
        || after.additions != before_noload.additions) return 57;
#else
    /* Pinned musl reports its RTLD_NOLOAD reference through dlpi_adds. */
    if (after.additions == before_noload.additions) return 66;
#endif
#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (after.visits != 4 || !after.nonzero_additions || map->l_next != NULL
        || map->l_prev == NULL) return 58;
    dlerror();
    if (dlsym(RTLD_DEFAULT, "bounded_plugin_value") != NULL || dlerror() == NULL) return 59;
#endif

    if (dlclose(workers[0].handle) != 0 || dlclose(workers[1].handle) != 0) return 60;
    if (dlsym(noload_handle, "bounded_plugin_value") != (void *)plugin_value) return 61;
    if (dlclose(noload_handle) != 0) return 62;
    if (dlsym(lazy_noload_handle, "bounded_plugin_value") != (void *)plugin_value) return 67;
    if (dlclose(lazy_noload_handle) != 0) return 70;
    if (dlsym(nodelete_noload_handle, "bounded_plugin_value") != (void *)plugin_value) return 71;
    if (dlclose(nodelete_noload_handle) != 0) return 72;
    if (dlsym(lazy_nodelete_noload_handle, "bounded_plugin_value") != (void *)plugin_value)
        return 73;
    if (dlclose(lazy_nodelete_noload_handle) != 0) return 74;
    void *nodelete_reopen =
        dlopen("libbounded-plugin.so", RTLD_LAZY | RTLD_NODELETE | RTLD_LOCAL);
    if (nodelete_reopen == NULL) return 75;
    int *reopen_legacy_init_runs =
        dlsym(nodelete_reopen, "bounded_plugin_legacy_init_runs");
    int *reopen_constructor_runs = dlsym(nodelete_reopen, "bounded_plugin_constructor_runs");
    if (dlsym(nodelete_reopen, "bounded_plugin_value") != (void *)plugin_value
        || reopen_legacy_init_runs == NULL || reopen_constructor_runs == NULL
        || *reopen_legacy_init_runs != 1 || *reopen_constructor_runs != 1
        || *initializer_order != 2) return 75;
    if (dlclose(nodelete_reopen) != 0) return 76;
#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (dlsym(handle, "bounded_plugin_value") != NULL || dlerror() == NULL) return 77;
    handle = dlopen("libbounded-plugin.so", RTLD_LAZY | RTLD_NODELETE | RTLD_LOCAL);
    if (handle == NULL || dlsym(handle, "bounded_plugin_value") != (void *)plugin_value) return 78;
    if (dlopen("libbounded-extra.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || dlerror() == NULL) return 79;
    struct graph_observation final = {0, 0, 0};
    if (dl_iterate_phdr(observe_graph, &final) != 0 || final.visits != 4
        || !final.plugin_seen || !final.nonzero_additions) return 80;
    if (dlclose(handle) != 0) return 81;
#endif
    return 0;
}
