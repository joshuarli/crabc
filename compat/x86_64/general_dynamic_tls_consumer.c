#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { GENERATIONS = 40, WORKERS = 4 };
typedef int *(*address_fn)(void);
static address_fn addresses[GENERATIONS];
static int (*checks[GENERATIONS])(void);
static void *handles[GENERATIONS];
static atomic_int stage, ready, completed, concurrent_start;
static int *worker_addresses[WORKERS][GENERATIONS];

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "runtime TLS check failed: line %d: %s; %s\n", __LINE__, #condition, dlerror()); \
    abort(); } } while (0)

static void *existing_worker(void *argument)
{
    unsigned id = (uintptr_t)argument;
    atomic_fetch_add(&ready, 1);
    for (int generation = 0; generation < GENERATIONS; ++generation) {
        while (atomic_load(&stage) <= generation) { }
        int *address = addresses[generation]();
        CHECK(checks[generation]() == 0 && *address == 17 + generation);
        CHECK(dlsym(handles[generation], "growth_value") == address);
        worker_addresses[id][generation] = address;
        *address = 1000 + 100 * id + generation;
        for (int old = 0; old <= generation; ++old) {
            CHECK(addresses[old]() == worker_addresses[id][old]);
            CHECK(*addresses[old]() == 1000 + 100 * (int)id + old);
        }
        /* Each pending diagnostic belongs to this actual TLS allocation. */
        CHECK(!dlsym(handles[generation], "missing_worker_symbol"));
        const char *error = dlerror();
        CHECK(error && strstr(error, "missing_worker_symbol") && !dlerror());
        atomic_fetch_add(&completed, 1);
    }
    return 0;
}

static void *new_worker(void *argument)
{
    (void)argument;
    for (int generation = 0; generation < GENERATIONS; ++generation)
        CHECK(checks[generation]() == 0 && *addresses[generation]() == 17 + generation);
    return 0;
}

static void *concurrent_worker(void *argument)
{
    (void)argument;
    atomic_fetch_add(&ready, 1);
    while (!atomic_load(&concurrent_start)) { }
    void *handle = dlopen("libgrowth40.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(handle);
    int (*count)(void) = (int (*)(void))dlsym(handle, "growth_constructed");
    CHECK(count && count() == 1);
    CHECK(dlclose(handle) == 0);
    return handle;
}

static int visit(struct dl_phdr_info *info, size_t size, void *argument)
{
    int *count = argument;
    CHECK(size >= sizeof *info && info->dlpi_phdr && info->dlpi_phnum);
    if (strstr(info->dlpi_name, "libgrowth")) {
        ++*count;
        CHECK(info->dlpi_tls_modid && info->dlpi_tls_data);
    }
    return 0;
}

int main(void)
{
    pthread_t workers[WORKERS];
    for (uintptr_t index = 0; index < WORKERS; ++index)
        CHECK(!pthread_create(&workers[index], 0, existing_worker, (void *)index));
    while (atomic_load(&ready) != WORKERS) { }
    CHECK(!dlopen("libgrowth0.so", RTLD_NOW | RTLD_NOLOAD));
    CHECK(dlerror() && !dlerror());
    int *main_addresses[GENERATIONS];
    for (int generation = 0; generation < GENERATIONS; ++generation) {
        char name[64];
        snprintf(name, sizeof name, "libgrowth%d.so", generation);
        handles[generation] = dlopen(name, RTLD_NOW | RTLD_LOCAL);
        CHECK(handles[generation]);
        addresses[generation] = (address_fn)dlsym(handles[generation], "growth_address");
        checks[generation] = (int (*)(void))dlsym(handles[generation], "growth_check");
        CHECK(addresses[generation] && checks[generation] && !checks[generation]());
        main_addresses[generation] = addresses[generation]();
        CHECK(*main_addresses[generation] == 17 + generation);
        *main_addresses[generation] = 2000 + generation;
        CHECK(!dlsym(RTLD_DEFAULT, "growth_value"));
        CHECK(dlerror() && !dlerror());
        Dl_info info;
        CHECK(dladdr((void *)addresses[generation], &info));
        CHECK(strstr(info.dli_fname, name) && !strcmp(info.dli_sname, "growth_address"));
        CHECK(info.dli_saddr == (void *)addresses[generation]);
        struct link_map *map = 0;
        CHECK(!dlinfo(handles[generation], RTLD_DI_LINKMAP, &map));
        CHECK(map && strstr(map->l_name, name) && map->l_ld && map->l_addr);
        atomic_store(&stage, generation + 1);
        while (atomic_load(&completed) != WORKERS * (generation + 1)) { }
        for (int old = 0; old <= generation; ++old) {
            CHECK(addresses[old]() == main_addresses[old] && *addresses[old]() == 2000 + old);
            for (int worker = 0; worker < WORKERS; ++worker)
                CHECK(worker_addresses[worker][old] != main_addresses[old]);
        }
        CHECK(dlclose(handles[generation]) == 0 && dlclose(handles[generation]) == 0);
        CHECK(dlopen(name, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE) == handles[generation]);
        CHECK(*addresses[generation]() == 2000 + generation);
    }
    for (int index = 0; index < WORKERS; ++index) CHECK(!pthread_join(workers[index], 0));
    CHECK(!pthread_create(&workers[0], 0, new_worker, 0));
    CHECK(!pthread_join(workers[0], 0));
    atomic_store(&ready, 0);
    for (int index = 0; index < WORKERS; ++index)
        CHECK(!pthread_create(&workers[index], 0, concurrent_worker, 0));
    while (atomic_load(&ready) != WORKERS) { }
    atomic_store(&concurrent_start, 1);
    void *identity = 0;
    for (int index = 0; index < WORKERS; ++index) {
        void *result;
        CHECK(!pthread_join(workers[index], &result));
        if (identity) CHECK(identity == result);
        identity = result;
    }
    int count = 0;
    CHECK(!dl_iterate_phdr(visit, &count) && count == GENERATIONS + 1);
    CHECK(dlopen("libgrowth0.so", RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL) == handles[0]);
    CHECK(dlsym(RTLD_DEFAULT, "growth_value") == main_addresses[0]);
    puts("runtime TLS: old/new workers, 41 modules, retained addresses, recursive/concurrent constructors");
    return 0;
}
