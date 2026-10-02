#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c) do { if (!(c)) { dprintf(2, "loader TLS growth line=%d\n", __LINE__); _Exit(82); } } while (0)
#define MODULES 33
#define WORKERS 2

struct module {
    void *handle;
    int *(*cell)(void);
    unsigned char *(*zero)(void);
    int (*ready)(void);
};
static struct module modules[MODULES];
static int *(*root_cell)(void), *(*dependency_cell)(void);
static int (*root_ready)(void), (*dependency_ready)(void);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned stage, started, completed[3];
static int *worker_addresses[WORKERS][MODULES + 2];
static atomic_int growth_finished;
static atomic_uint observations[WORKERS];

static void wait_stage(unsigned wanted)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (stage < wanted) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void complete(unsigned index)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    ++completed[index];
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static int *fresh_module(unsigned index)
{
    CHECK(modules[index].ready());
    int *cell = modules[index].cell();
    CHECK(*cell == 301 + (int)index);
    unsigned char *zero = modules[index].zero();
    CHECK(((uintptr_t)zero & 4095) == 0);
    for (unsigned n = 0; n < 257; ++n) CHECK(zero[n] == 0);
    return cell;
}

static void *early_worker(void *argument)
{
    unsigned number = (unsigned)(uintptr_t)argument;
    CHECK(pthread_mutex_lock(&lock) == 0);
    ++started;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    wait_stage(1);
    CHECK(root_ready() && dependency_ready());
    int **addresses = worker_addresses[number - 1];
    addresses[0] = root_cell();
    addresses[1] = dependency_cell();
    CHECK(*addresses[0] == 101 && *addresses[1] == 201);
    *addresses[0] = 1000 + (int)number;
    *addresses[1] = 2000 + (int)number;
    addresses[2] = fresh_module(0);
    *addresses[2] = 3000 + (int)number;
    modules[0].zero()[256] = (unsigned char)number;
    complete(0);
    do {
        CHECK(root_cell() == addresses[0] && dependency_cell() == addresses[1]);
        CHECK(*addresses[0] == 1000 + (int)number && *addresses[1] == 2000 + (int)number);
        CHECK(modules[0].cell() == addresses[2] && *addresses[2] == 3000 + (int)number);
        CHECK(modules[0].zero()[256] == number);
        atomic_fetch_add_explicit(&observations[number - 1], 1, memory_order_release);
        sched_yield();
    } while (!atomic_load_explicit(&growth_finished, memory_order_acquire));
    wait_stage(2);
    CHECK(root_cell() == addresses[0] && dependency_cell() == addresses[1]);
    CHECK(*addresses[0] == 1000 + (int)number && *addresses[1] == 2000 + (int)number);
    CHECK(modules[0].cell() == addresses[2] && *addresses[2] == 3000 + (int)number);
    CHECK(modules[0].zero()[256] == number);
    for (unsigned n = 1; n < MODULES; ++n) {
        addresses[n + 2] = fresh_module(n);
        *addresses[n + 2] = 3000 + 10 * (int)n + (int)number;
        modules[n].zero()[256] = (unsigned char)number;
    }
    complete(1);
    wait_stage(3);
    CHECK(root_ready() && dependency_ready());
    for (unsigned n = 0; n < MODULES; ++n) {
        CHECK(modules[n].ready() && modules[n].cell() == addresses[n + 2]);
        CHECK(*addresses[n + 2] == 3000 + 10 * (int)n + (int)number);
        CHECK(modules[n].zero()[256] == number);
    }
    complete(2);
    return 0;
}

static void *late_worker(void *argument)
{
    (void)argument;
    CHECK(root_ready() && dependency_ready());
    CHECK(*root_cell() == 101 && *dependency_cell() == 201);
    for (unsigned n = 0; n < MODULES; ++n) {
        int *cell = fresh_module(n);
        CHECK(cell != worker_addresses[0][n + 2] && cell != worker_addresses[1][n + 2]);
        *cell = 4000 + (int)n;
    }
    return 0;
}

static void advance(unsigned next)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    stage = next;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    while (completed[next - 1] != WORKERS) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void open_module(unsigned index)
{
    char path[80];
    CHECK(snprintf(path, sizeof path, "libloader112-module-%02u.so", index) > 0);
    struct module *module = &modules[index];
    module->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    CHECK(module->handle);
    module->cell = (int *(*)(void))dlsym(module->handle, "loader112_cell");
    module->zero = (unsigned char *(*)(void))dlsym(module->handle, "loader112_zero");
    module->ready = (int (*)(void))dlsym(module->handle, "loader112_ready");
    CHECK(module->cell && module->zero && module->ready && module->ready());
}

int main(void)
{
    pthread_t workers[WORKERS];
    for (unsigned n = 0; n < WORKERS; ++n)
        CHECK(pthread_create(&workers[n], 0, early_worker, (void *)(uintptr_t)(n + 1)) == 0);
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (started != WORKERS) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    void *root = dlopen("libloader112-root.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(root);
    root_cell = (int *(*)(void))dlsym(root, "loader112_root_cell");
    dependency_cell = (int *(*)(void))dlsym(root, "loader112_dependency_cell");
    root_ready = (int (*)(void))dlsym(root, "loader112_root_ready");
    dependency_ready = (int (*)(void))dlsym(root, "loader112_dependency_ready");
    CHECK(root_cell && dependency_cell && root_ready && dependency_ready);
    CHECK(root_ready() && dependency_ready() && *root_cell() == 111 && *dependency_cell() == 211);
    open_module(0);
    CHECK(*modules[0].cell() == 311);
    int *main_addresses[MODULES];
    main_addresses[0] = modules[0].cell();
    *main_addresses[0] = 3100;
    advance(1);
    for (unsigned n = 0; n < WORKERS; ++n)
        while (!atomic_load_explicit(&observations[n], memory_order_acquire)) sched_yield();
    for (unsigned n = 1; n < MODULES; ++n) {
        open_module(n);
        main_addresses[n] = fresh_module(n);
        *main_addresses[n] = 3100 + (int)n;
    }
    atomic_store_explicit(&growth_finished, 1, memory_order_release);
    advance(2);
    pthread_t late;
    CHECK(pthread_create(&late, 0, late_worker, 0) == 0);
    CHECK(pthread_join(late, 0) == 0);
    CHECK(dlclose(root) == 0);
    CHECK(dlopen("libloader112-root.so", RTLD_NOW | RTLD_NOLOAD) == root);
    for (unsigned n = 0; n < MODULES; ++n) {
        char path[80];
        CHECK(snprintf(path, sizeof path, "libloader112-module-%02u.so", n) > 0);
        CHECK(dlclose(modules[n].handle) == 0);
        CHECK(dlopen(path, RTLD_NOW | RTLD_NOLOAD) == modules[n].handle);
        CHECK(modules[n].ready() && modules[n].cell() == main_addresses[n]);
        CHECK(*main_addresses[n] == 3100 + (int)n);
        CHECK(main_addresses[n] != worker_addresses[0][n + 2]);
        CHECK(main_addresses[n] != worker_addresses[1][n + 2]);
        CHECK(worker_addresses[0][n + 2] != worker_addresses[1][n + 2]);
    }
    CHECK(root_ready() && dependency_ready() && *root_cell() == 111 && *dependency_cell() == 211);
    advance(3);
    for (unsigned n = 0; n < WORKERS; ++n) CHECK(pthread_join(workers[n], 0) == 0);
    puts("loader TLS growth: 33 modules, existing/fresh workers, nested constructors, retained close PASS");
    return 0;
}
