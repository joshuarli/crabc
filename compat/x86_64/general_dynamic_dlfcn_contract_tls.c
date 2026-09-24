/* Musl differential for DTV growth racing thread creation and exit.
 *
 * A loader thread publishes the eight TLS modules libcc_ok{1,3,...,15}.so
 * (general_dynamic_dlfcn_contract_dso.c CC_OK) while the main thread keeps
 * creating short-lived threads. Each new thread reads every module published
 * before it started, must see the initial template value, writes and rereads
 * its own copy, and exits. A worker created before any load and the main
 * thread read all eight afterwards and must still see their own values.
 * Pinned musl 1.2.6 ldso/dynlink.c::install_new_tls extends every existing
 * thread's DTV under the thread-list lock and new threads copy the current
 * TLS image, so no reader ever observes another thread's copy or a stale
 * template. Only interleaving-independent counts are printed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

enum { MODULES = 8, THREADS = 96 };

static atomic_int published;
static atomic_int loads_done;
static long loader_violations;

/* Each odd CC_OK module exports cc_ok_tls<i>; dlsym yields this thread's. */
static int *module_address(int module)
{
    char symbol[32];
    snprintf(symbol, sizeof symbol, "cc_ok_tls%d", module * 2 + 1);
    return dlsym(RTLD_DEFAULT, symbol);
}

static void *loader(void *argument)
{
    (void)argument;
    for (int module = 0; module < MODULES; ++module) {
        char name[32];
        snprintf(name, sizeof name, "libcc_ok%d.so", module * 2 + 1);
        if (!dlopen(name, RTLD_NOW | RTLD_GLOBAL)) ++loader_violations;
        atomic_store_explicit(&published, module + 1, memory_order_release);
    }
    atomic_store(&loads_done, 1);
    return 0;
}

/* Reads published modules, then proves this copy is private. */
static long check_modules(int count, int marker)
{
    long violations = 0;
    for (int module = 0; module < count; ++module) {
        int *value = module_address(module);
        if (!value || *value != 800 + module * 2 + 1) { ++violations; continue; }
        *value = marker + module;
    }
    for (int module = 0; module < count; ++module) {
        int *value = module_address(module);
        if (!value || *value != marker + module) ++violations;
    }
    return violations;
}

static void *short_thread(void *argument)
{
    long *violations = argument;
    int count = atomic_load_explicit(&published, memory_order_acquire);
    *violations = check_modules(count, 5000);
    return 0;
}

static pthread_barrier_t barrier;
static void *early_worker(void *argument)
{
    long *violations = argument;
    pthread_barrier_wait(&barrier);
    *violations = check_modules(MODULES, 7000);
    return 0;
}

int main(void)
{
    long early = -1, violations = 0;
    pthread_t worker, load;
    if (pthread_barrier_init(&barrier, 0, 2) || pthread_create(&worker, 0, early_worker, &early)) return 3;
    if (pthread_create(&load, 0, loader, 0)) return 3;
    int created = 0;
    for (int round = 0; round < THREADS || !atomic_load(&loads_done); ++round) {
        pthread_t thread;
        long result = -1;
        if (pthread_create(&thread, 0, short_thread, &result) || pthread_join(thread, 0)) return 4;
        violations += result;
        ++created;
    }
    pthread_join(load, 0);
    pthread_barrier_wait(&barrier);
    pthread_join(worker, 0);
    long main_violations = check_modules(MODULES, 9000);
    long after = 0;
    pthread_t thread;
    if (pthread_create(&thread, 0, short_thread, &after) || pthread_join(thread, 0)) return 4;
    printf("loader violations=%ld\n", loader_violations);
    printf("short threads ran=%d violations=%ld\n", created >= THREADS, violations);
    printf("early worker violations=%ld main violations=%ld late thread violations=%ld\n", early, main_violations, after);
    puts("tls contract: complete");
    return 0;
}
