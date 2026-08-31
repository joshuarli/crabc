#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

#ifndef CRABC_PUBLIC_DLFCN_FREESTANDING
#include <pthread.h>
#endif

extern int mid_value(void);
extern int *mid_leaf_data_address(void);

_Static_assert(RTLD_LAZY == 1, "RTLD_LAZY x86 ABI");
_Static_assert(RTLD_NOW == 2, "RTLD_NOW x86 ABI");
_Static_assert(RTLD_NOLOAD == 4, "RTLD_NOLOAD x86 ABI");
_Static_assert(RTLD_GLOBAL == 0x100, "RTLD_GLOBAL x86 ABI");
_Static_assert(RTLD_LOCAL == 0, "RTLD_LOCAL x86 ABI");
_Static_assert(RTLD_NODELETE == 4096, "RTLD_NODELETE x86 ABI");
_Static_assert(RTLD_DI_LINKMAP == 2, "RTLD_DI_LINKMAP x86 ABI");
_Static_assert(sizeof(Dl_info) == 32, "Dl_info x86 LP64 layout");
_Static_assert(offsetof(Dl_info, dli_saddr) == 24, "Dl_info tail offset");
_Static_assert(sizeof(struct link_map) == 40, "link_map x86 LP64 layout");
_Static_assert(offsetof(struct link_map, l_prev) == 32, "link_map tail offset");
_Static_assert(sizeof(struct dl_phdr_info) == 64, "dl_phdr_info x86 LP64 layout");
_Static_assert(offsetof(struct dl_phdr_info, dlpi_tls_data) == 56,
               "dl_phdr_info tail offset");

static void *(*const typed_dlopen)(const char *, int) = dlopen;
static void *(*const typed_dlsym)(void *restrict, const char *restrict) = dlsym;
static int (*const typed_dlclose)(void *) = dlclose;
static char *(*const typed_dlerror)(void) = dlerror;
static int (*const typed_dladdr)(const void *, Dl_info *) = dladdr;
static int (*const typed_dlinfo)(void *, int, void *) = dlinfo;
static int (*const typed_dl_iterate_phdr)(
    int (*)(struct dl_phdr_info *, size_t, void *), void *) = dl_iterate_phdr;

struct observed_graph {
    int main_seen;
    int mid_seen;
    int leaf_seen;
    int visits;
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

static int text_equal(const char *left, const char *right) {
    if (left == NULL || right == NULL) return 0;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static int observe_image(struct dl_phdr_info *information, size_t size, void *opaque) {
    struct observed_graph *observed = opaque;
    if (size < offsetof(struct dl_phdr_info, dlpi_phnum) + sizeof(information->dlpi_phnum)
        || information->dlpi_phdr == NULL || information->dlpi_phnum == 0) {
        return 91;
    }
    ++observed->visits;
    if (observed->visits == 1) {
        observed->main_seen = 1;
    } else if (contains(information->dlpi_name, "libmid-public-dlfcn.so")) {
        observed->mid_seen = 1;
    } else if (contains(information->dlpi_name, "libleaf-public-dlfcn.so")) {
        observed->leaf_seen = 1;
    }
    return 0;
}

static int stop_after_one(struct dl_phdr_info *information, size_t size, void *opaque) {
    (void)information;
    (void)size;
    ++*(int *)opaque;
    return 73;
}

struct error_worker {
    volatile int ready;
    volatile int go;
    volatile int done;
    const char *symbol;
    char *error;
    int second_was_null;
};

static void *concurrent_handle;

static void *error_worker_main(void *opaque) {
    struct error_worker *worker = opaque;
    if (typed_dlsym(concurrent_handle, worker->symbol) != NULL) {
        worker->done = -1;
        return NULL;
    }
    __atomic_store_n(&worker->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&worker->go, __ATOMIC_ACQUIRE)) { }
    worker->error = typed_dlerror();
    worker->second_was_null = typed_dlerror() == NULL;
    __atomic_store_n(&worker->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

#ifdef CRABC_PUBLIC_DLFCN_FREESTANDING
extern long crabc_spawn_dlfcn_thread(void *(*)(void *), void *, void *, int *);
static unsigned char worker_stacks[2][32768] __attribute__((aligned(16)));

static int run_concurrent_errors(struct error_worker *workers) {
    int child_tids[2] = {0, 0};
    for (int index = 0; index < 2; ++index) {
        void *top = worker_stacks[index] + sizeof(worker_stacks[index]);
        if (crabc_spawn_dlfcn_thread(error_worker_main, &workers[index], top,
                                     &child_tids[index]) <= 0) {
            return 0;
        }
    }
    while (!__atomic_load_n(&workers[0].ready, __ATOMIC_ACQUIRE)
           || !__atomic_load_n(&workers[1].ready, __ATOMIC_ACQUIRE)) { }
    __atomic_store_n(&workers[0].go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&workers[1].go, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&workers[0].done, __ATOMIC_ACQUIRE)
           || !__atomic_load_n(&workers[1].done, __ATOMIC_ACQUIRE)) { }
    while (__atomic_load_n(&child_tids[0], __ATOMIC_ACQUIRE) != 0
           || __atomic_load_n(&child_tids[1], __ATOMIC_ACQUIRE) != 0) { }
    return 1;
}
#else
static int run_concurrent_errors(struct error_worker *workers) {
    pthread_t threads[2];
    if (pthread_create(&threads[0], NULL, error_worker_main, &workers[0]) != 0
        || pthread_create(&threads[1], NULL, error_worker_main, &workers[1]) != 0) {
        return 0;
    }
    while (!__atomic_load_n(&workers[0].ready, __ATOMIC_ACQUIRE)
           || !__atomic_load_n(&workers[1].ready, __ATOMIC_ACQUIRE)) { }
    __atomic_store_n(&workers[0].go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&workers[1].go, 1, __ATOMIC_RELEASE);
    return pthread_join(threads[0], NULL) == 0 && pthread_join(threads[1], NULL) == 0;
}
#endif

int main(void) {
    (void)typed_dlopen;
    (void)typed_dlclose;
    (void)typed_dladdr;
    (void)typed_dlinfo;
    (void)typed_dl_iterate_phdr;
    if (mid_value() != 42) return 40;

#ifdef CRABC_PUBLIC_DLFCN_MALFORMED
    if (typed_dlopen(NULL, RTLD_NOW | RTLD_LOCAL) != NULL) return 41;
    char *malformed = typed_dlerror();
    if (malformed == NULL || malformed[0] == '\0' || typed_dlerror() != NULL) return 42;
    Dl_info address = {(void *)1, (void *)1, (void *)1, (void *)1};
    if (typed_dladdr((const void *)&mid_value, &address) != 0
        || address.dli_fname != NULL || address.dli_fbase != NULL
        || address.dli_sname != NULL || address.dli_saddr != NULL) return 43;
    struct link_map *map = (void *)1;
    if (typed_dlinfo(NULL, RTLD_DI_LINKMAP, &map) != -1) return 44;
    struct observed_graph observed = {0, 0, 0, 0};
    if (typed_dl_iterate_phdr(observe_image, &observed) != -1) return 45;
    return 0;
#else
    void *main_handle = typed_dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
    void *mid_one = typed_dlopen("libmid-public-dlfcn.so", RTLD_NOW | RTLD_LOCAL);
    void *mid_two = typed_dlopen("libmid-public-dlfcn.so", RTLD_LAZY | RTLD_LOCAL);
    void *leaf = typed_dlopen("libleaf-public-dlfcn.so", RTLD_NOW | RTLD_LOCAL);
    if (main_handle == NULL || mid_one == NULL || mid_one != mid_two || leaf == NULL) return 46;

    typed_dlerror();
    void *main_noload = typed_dlopen(NULL, RTLD_NOLOAD);
    if (main_noload != main_handle) return 69;
    if (typed_dlerror() != NULL) return 70;

    typed_dlerror();
    if (typed_dlclose(NULL) != 1) return 63;
    char *null_close = typed_dlerror();
    if (!text_equal(null_close, "Invalid library handle 0")
        || typed_dlerror() != NULL) return 64;

    typed_dlerror();
    if (typed_dlsym(mid_one, "") != NULL) return 65;
    char *empty_symbol = typed_dlerror();
    if (!text_equal(empty_symbol, "Symbol not found: ")
        || typed_dlerror() != NULL) return 66;

    Dl_info null_address = {
        (const char *)(uintptr_t)1,
        (void *)(uintptr_t)2,
        (const char *)(uintptr_t)3,
        (void *)(uintptr_t)4,
    };
    typed_dlerror();
    if (typed_dladdr(NULL, &null_address) != 0
        || null_address.dli_fname != (const char *)(uintptr_t)1
        || null_address.dli_fbase != (void *)(uintptr_t)2
        || null_address.dli_sname != (const char *)(uintptr_t)3
        || null_address.dli_saddr != (void *)(uintptr_t)4) return 67;
    if (typed_dlerror() != NULL) return 68;

    Dl_info no_image_address = {
        (const char *)(uintptr_t)5,
        (void *)(uintptr_t)6,
        (const char *)(uintptr_t)7,
        (void *)(uintptr_t)8,
    };
    typed_dlerror();
    if (typed_dladdr((const void *)(uintptr_t)1, &no_image_address) != 0
        || no_image_address.dli_fname != (const char *)(uintptr_t)5
        || no_image_address.dli_fbase != (void *)(uintptr_t)6
        || no_image_address.dli_sname != (const char *)(uintptr_t)7
        || no_image_address.dli_saddr != (void *)(uintptr_t)8) return 71;
    if (typed_dlerror() != NULL) return 72;

    typed_dlerror();
    void *mid_symbol = typed_dlsym(mid_one, "mid_value");
    if (mid_symbol != (void *)&mid_value || ((int (*)(void))mid_symbol)() != 42
        || typed_dlerror() != NULL || typed_dlsym(RTLD_DEFAULT, "mid_value") != mid_symbol) {
        return 47;
    }
    void *leaf_symbol = typed_dlsym(mid_one, "leaf_data");
    if (leaf_symbol != (void *)mid_leaf_data_address()
        || typed_dlsym(leaf, "mid_value") != NULL || typed_dlerror() == NULL
        || typed_dlerror() != NULL) return 48;

    Dl_info address;
    if (typed_dladdr(mid_symbol, &address) != 1 || address.dli_fbase == NULL
        || address.dli_saddr != mid_symbol || !contains(address.dli_fname, "libmid-public-dlfcn.so")
        || !text_equal(address.dli_sname, "mid_value")) return 49;
    struct link_map *unsupported_map = (void *)(uintptr_t)1;
    struct link_map *map = NULL;
    typed_dlerror();
    if (typed_dlinfo(mid_one, -7, &unsupported_map) != -1
        || unsupported_map != (void *)(uintptr_t)1) return 60;
    if (typed_dlinfo(mid_one, RTLD_DI_LINKMAP, &map) != 0 || map == NULL) return 61;
    char *unsupported_request = typed_dlerror();
    if (!text_equal(unsupported_request, "Unsupported request -7")
        || typed_dlerror() != NULL) return 62;
    if (map->l_addr != (ElfW(Addr))address.dli_fbase || map->l_ld == NULL
        || !contains(map->l_name, "libmid-public-dlfcn.so") || map->l_prev == NULL
        || map->l_prev->l_ld == NULL || map->l_next == NULL
        || map->l_next->l_ld == NULL) return 50;

    struct observed_graph observed = {0, 0, 0, 0};
    if (typed_dl_iterate_phdr(observe_image, &observed) != 0
#ifdef CRABC_PUBLIC_DLFCN_FREESTANDING
        || observed.visits != 3
#else
        || observed.visits < 3
#endif
        || !observed.main_seen || !observed.mid_seen || !observed.leaf_seen) return 51;
    int visits = 0;
    if (typed_dl_iterate_phdr(stop_after_one, &visits) != 73 || visits != 1) return 52;

    concurrent_handle = mid_one;
    struct error_worker workers[2] = {
        {0, 0, 0, "crabc_missing_thread_one", NULL, 0},
        {0, 0, 0, "crabc_missing_thread_two", NULL, 0},
    };
    if (!run_concurrent_errors(workers) || workers[0].done != 1 || workers[1].done != 1
        || workers[0].error == NULL || workers[1].error == NULL
        || workers[0].error == workers[1].error
        || !workers[0].second_was_null || !workers[1].second_was_null) return 53;

#ifdef CRABC_PUBLIC_DLFCN_FREESTANDING
    /* Cross the 32-slot lifetime bound while keeping only two TIDs live. */
    for (int round = 0; round < 20; ++round) {
        struct error_worker reclaimed[2] = {
            {0, 0, 0, "crabc_reclaimed_thread_one", NULL, 0},
            {0, 0, 0, "crabc_reclaimed_thread_two", NULL, 0},
        };
        if (!run_concurrent_errors(reclaimed)
            || reclaimed[0].error == NULL || reclaimed[1].error == NULL
            || reclaimed[0].error == reclaimed[1].error
            || !reclaimed[0].second_was_null || !reclaimed[1].second_was_null) return 59;
    }
#endif

    typed_dlerror();
    if (typed_dlopen("libcrabc-not-loaded.so", RTLD_NOW | RTLD_LOCAL) != NULL
        || typed_dlerror() == NULL || typed_dlerror() != NULL) return 54;

#ifdef CRABC_PUBLIC_DLFCN_FREESTANDING
    if (typed_dlsym(RTLD_NEXT, "mid_value") != NULL || typed_dlerror() == NULL
        || typed_dlopen("libmid-public-dlfcn.so", RTLD_NOW | RTLD_GLOBAL) != NULL
        || typed_dlerror() == NULL) return 55;
#else
    if (typed_dlsym(RTLD_NEXT, "mid_value") == NULL || typed_dlerror() != NULL
        || typed_dlopen("libmid-public-dlfcn.so", RTLD_NOW | RTLD_GLOBAL) == NULL) return 55;
#endif

    if (typed_dlclose(mid_one) != 0 || typed_dlclose(mid_two) != 0) return 56;
#ifdef CRABC_PUBLIC_DLFCN_FREESTANDING
    if (typed_dlsym(mid_one, "mid_value") != NULL || typed_dlerror() == NULL
        || typed_dlclose(mid_one) != -1 || typed_dlerror() == NULL
        || typed_dlinfo(mid_one, RTLD_DI_LINKMAP, &map) != -1) return 57;
#endif
    if (typed_dlclose(leaf) != 0 || typed_dlclose(main_handle) != 0) return 58;
    return 0;
#endif
}
