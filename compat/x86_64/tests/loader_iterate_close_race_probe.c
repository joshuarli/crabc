#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*state_fn)(int *, int *, int *, int *);
typedef void (*set_tls_fn)(int, int);

struct race {
    atomic_int phase;
    int callbacks;
    int failed;
    uintptr_t image;
    uintptr_t headers;
    size_t header_count;
    size_t module;
    uintptr_t tls;
    char name[256];
    state_fn state;
    set_tls_fn set_tls;
};

static int state_is(state_fn state, int constructors, int destructors,
                    int initialized, int zero)
{
    int actual_constructors, actual_destructors, actual_initialized, actual_zero;
    return state(&actual_constructors, &actual_destructors,
                 &actual_initialized, &actual_zero) == 0x51ac
        && actual_constructors == constructors && actual_destructors == destructors
        && actual_initialized == initialized && actual_zero == zero;
}

static int inspect(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct race *race = opaque;
    const char *name = strrchr(info->dlpi_name, '/');
    name = name ? name + 1 : info->dlpi_name;
    if (strcmp(name, "libloader-iterate-close-race.so")) return 0;
    ++race->callbacks;
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum
        || !info->dlpi_tls_modid || !info->dlpi_tls_data
        || strlen(info->dlpi_name) >= sizeof(race->name)) {
        race->failed = 1;
        return 1;
    }
    race->image = info->dlpi_addr;
    race->headers = (uintptr_t)info->dlpi_phdr;
    race->header_count = info->dlpi_phnum;
    race->module = info->dlpi_tls_modid;
    race->tls = (uintptr_t)info->dlpi_tls_data;
    strcpy(race->name, info->dlpi_name);
    race->set_tls(41, 43);
    if (!state_is(race->state, 1, 0, 41, 43)) race->failed = 2;
    atomic_store_explicit(&race->phase, 1, memory_order_release);
    while (atomic_load_explicit(&race->phase, memory_order_acquire) != 2)
        sched_yield();
    if (race->image != info->dlpi_addr || race->headers != (uintptr_t)info->dlpi_phdr
        || race->header_count != info->dlpi_phnum
        || race->module != info->dlpi_tls_modid
        || race->tls != (uintptr_t)info->dlpi_tls_data
        || strcmp(race->name, info->dlpi_name)
        || !state_is(race->state, 1, 0, 41, 43)) race->failed = 3;
    return 0;
}

static void *iterate(void *opaque)
{
    struct race *race = opaque;
    if (dl_iterate_phdr(inspect, race) != 0 && !race->failed) race->failed = 4;
    return 0;
}

static int count_images(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct race *race = opaque;
    const char *name = strrchr(info->dlpi_name, '/');
    (void)size;
    name = name ? name + 1 : info->dlpi_name;
    if (strcmp(name, "libloader-iterate-close-race.so")) return 0;
    ++race->callbacks;
    if (race->image != info->dlpi_addr || race->headers != (uintptr_t)info->dlpi_phdr
        || race->header_count != info->dlpi_phnum
        || race->module != info->dlpi_tls_modid
        || strcmp(race->name, info->dlpi_name)) race->failed = 5;
    return 0;
}

static int count_static(struct dl_phdr_info *info, size_t size, void *opaque)
{
    int *count = opaque;
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum) return 1;
    ++*count;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "static")) {
        int count = 0;
        if (dl_iterate_phdr(count_static, &count) != 0 || count < 1) return 10;
        printf("static images=%d\n", count);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "dynamic")) return 11;
    void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 12; }
    state_fn state = (state_fn)dlsym(handle, "loader_iterate_close_race_state");
    set_tls_fn set_tls = (set_tls_fn)dlsym(handle, "loader_iterate_close_race_set_tls");
    if (!state || !set_tls || !state_is(state, 1, 0, 17, 0)) return 13;
    set_tls(23, 29);
    struct race race = { .state = state, .set_tls = set_tls };
    pthread_t thread;
    if (pthread_create(&thread, 0, iterate, &race)) return 14;
    while (atomic_load_explicit(&race.phase, memory_order_acquire) != 1)
        sched_yield();
    if (race.failed || race.callbacks != 1) return 15;
    if (dlclose(handle)) return 16;
    void *again = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!again) return 17;
    state_fn reopened = (state_fn)dlsym(again, "loader_iterate_close_race_state");
    if (again != handle || reopened != state || !state_is(reopened, 1, 0, 23, 29))
        return 18;
    atomic_store_explicit(&race.phase, 2, memory_order_release);
    if (pthread_join(thread, 0) || race.failed || race.callbacks != 1) return 19;
    race.callbacks = 0;
    if (dl_iterate_phdr(count_images, &race) || race.failed || race.callbacks != 1)
        return 20;
    if (dlclose(again) || !state_is(state, 1, 0, 23, 29)) return 21;
    printf("dynamic callbacks=1 reopen=same constructors=1 destructors=0 "
           "main_tls=23,29 worker_tls=41,43 module=%zu\n", race.module);
    return 0;
}
