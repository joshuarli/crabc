#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

#ifndef CRABC_BOUNDED_DLFCN_FREESTANDING
#include <pthread.h>
#endif

extern int mid_value(void);

struct graph_count {
    int visits;
    int tls_seen;
    int plugin_seen;
};

static int contains(const char *text, const char *needle) {
    if (text == NULL) return 0;
    for (size_t start = 0; text[start] != '\0'; ++start) {
        size_t offset = 0;
        while (needle[offset] != '\0' && text[start + offset] != '\0') ++offset;
        if (needle[offset] == '\0') return 1;
    }
    return 0;
}

static int count_graph(struct dl_phdr_info *info, size_t size, void *opaque) {
    struct graph_count *count = opaque;
    if (size != sizeof(*info)) return 1;
    ++count->visits;
    count->tls_seen |= contains(info->dlpi_name, "libbounded-tls.so");
    count->plugin_seen |= contains(info->dlpi_name, "libbounded-plugin.so");
    return 0;
}

#ifndef CRABC_BOUNDED_DLFCN_FREESTANDING
struct tls_functions {
    int (*initialized)(void);
    int (*zero_filled)(void);
    void (*set)(int, int);
};

static void *check_worker_tls(void *opaque) {
    struct tls_functions *tls = opaque;
    if (tls->initialized() != 9 || tls->zero_filled() != 0) return (void *)1;
    tls->set(71, 72);
    if (tls->initialized() != 71 || tls->zero_filled() != 72) return (void *)2;
    return NULL;
}

static int check_musl_tls(void) {
    void *handle = dlopen("libbounded-tls.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 10;
    struct tls_functions tls = {
        (int (*)(void))dlsym(handle, "bounded_plugin_tls_value"),
        (int (*)(void))dlsym(handle, "bounded_plugin_tbss_value"),
        (void (*)(int, int))dlsym(handle, "bounded_plugin_tls_set"),
    };
    if (tls.initialized == NULL || tls.zero_filled == NULL || tls.set == NULL
        || tls.initialized() != 9 || tls.zero_filled() != 0) return 11;
    tls.set(31, 32);
    pthread_t worker;
    void *worker_result = (void *)3;
    if (pthread_create(&worker, NULL, check_worker_tls, &tls) != 0
        || pthread_join(worker, &worker_result) != 0 || worker_result != NULL
        || tls.initialized() != 31 || tls.zero_filled() != 32) return 12;
    if (dlclose(handle) != 0) return 13;
    handle = dlopen("libbounded-tls.so", RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL || dlsym(handle, "bounded_plugin_tls_value") == NULL
        || tls.initialized() != 31 || tls.zero_filled() != 32) return 14;
    return dlclose(handle) == 0 ? 0 : 15;
}
#endif

int main(void) {
    if (mid_value() != 42) return 20;
    struct graph_count before = {0};
    if (dl_iterate_phdr(count_graph, &before) != 0 || before.plugin_seen
        || before.tls_seen) return 21;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (before.visits != 3
        || dlopen("libbounded-tls.so", RTLD_NOW | RTLD_LOCAL) != NULL) return 22;
    char *error = dlerror();
    if (!contains(error, "unsupported DSO metadata") || dlerror() != NULL) return 23;
    struct graph_count after_tls = {0};
    if (dl_iterate_phdr(count_graph, &after_tls) != 0
        || after_tls.visits != before.visits || after_tls.tls_seen
        || after_tls.plugin_seen) return 24;
    if (dlopen("libbounded-tls.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL
        || dlerror() == NULL || dlerror() != NULL) return 25;
#else
    int tls_status = check_musl_tls();
    if (tls_status != 0) return tls_status;
    struct graph_count after_tls = {0};
    if (dl_iterate_phdr(count_graph, &after_tls) != 0 || !after_tls.tls_seen
        || after_tls.visits != before.visits + 1) return 26;
#endif

    enum { REFERENCE_COUNT = 48 };
    void *handles[REFERENCE_COUNT];
    for (int index = 0; index < REFERENCE_COUNT; ++index) {
        int flags = RTLD_LOCAL;
        if (index % 4 == 0) flags |= RTLD_NOW;
        else if (index % 4 == 1) flags |= RTLD_LAZY;
        else if (index % 4 == 2) flags |= RTLD_NOW | RTLD_NOLOAD;
        else flags |= RTLD_LAZY | RTLD_NOLOAD | RTLD_NODELETE;
        handles[index] = dlopen("libbounded-plugin.so", flags);
        if (handles[index] == NULL || handles[index] != handles[0]) return 30;
    }
    int (*value)(void) = (int (*)(void))dlsym(handles[0], "bounded_plugin_value");
    int *legacy_runs = dlsym(handles[0], "bounded_plugin_legacy_init_runs");
    int *constructor_runs = dlsym(handles[0], "bounded_plugin_constructor_runs");
    if (value == NULL || value() != 77 || legacy_runs == NULL
        || constructor_runs == NULL || *legacy_runs != 1 || *constructor_runs != 1)
        return 31;
    struct graph_count loaded = {0};
    if (dl_iterate_phdr(count_graph, &loaded) != 0 || !loaded.plugin_seen
        || loaded.visits != before.visits +
#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
           1
#else
           2
#endif
       ) return 32;

    /* Close the first handle and alternating later handles while other
     * acquisitions still protect the same token. */
    for (int parity = 0; parity < 2; ++parity) {
        for (int index = parity; index < REFERENCE_COUNT - 1; index += 2) {
            if (dlclose(handles[index]) != 0
                || dlsym(handles[REFERENCE_COUNT - 1], "bounded_plugin_value")
                    != (void *)value) return 33;
        }
    }
    if (dlclose(handles[REFERENCE_COUNT - 1]) != 0) return 34;

#ifdef CRABC_BOUNDED_DLFCN_FREESTANDING
    if (dlsym(handles[0], "bounded_plugin_value") != NULL
        || dlerror() == NULL || dlerror() != NULL) return 35;
#endif
    void *reopened = dlopen("libbounded-plugin.so", RTLD_NOW | RTLD_LOCAL);
    if (reopened == NULL || reopened != handles[0]
        || dlsym(reopened, "bounded_plugin_value") != (void *)value
        || *legacy_runs != 1 || *constructor_runs != 1) return 36;
    if (dlclose(reopened) != 0) return 37;
    return 0;
}
