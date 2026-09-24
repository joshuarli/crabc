/* Musl differential for concurrent successful and failed dlopen while other
 * threads read through dlsym and dl_iterate_phdr.
 *
 * One opener publishes libcc_ok0..15.so (odd ones add TLS modules) as
 * RTLD_GLOBAL. One failer repeatedly opens libfr_root.so, whose TLS
 * dependency maps before a later dependency is missing or lacks a symbol
 * (see general_dynamic_dlfcn_contract_rollback.c). Two readers run until
 * both finish. Pinned musl 1.2.6 ldso/dynlink.c serializes dlopen under its
 * write lock and dlsym/dl_iterate_phdr successor reads under the read lock,
 * so a reader never observes a rolled-back object, every published global
 * definition stays resolvable, the image list and dlpi_adds only grow, and
 * each thread keeps its own dlerror text. Output is invariant counts only,
 * so interleaving does not change it.
 *
 * Usage: consumer missing|unresolved */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "general_dynamic_dlfcn_contract.h"

enum { SUCCESSES = 16, FAILURES = 48, READERS = 2 };

static atomic_int published;
static atomic_int finished;

static void *opener(void *argument)
{
    long *violations = argument;
    for (int index = 0; index < SUCCESSES; ++index) {
        char name[32], symbol[32];
        snprintf(name, sizeof name, "libcc_ok%d.so", index);
        void *handle = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
        if (!handle || dlerror()) { ++*violations; continue; }
        snprintf(symbol, sizeof symbol, "cc_ok_value%d", index);
        int *value = dlsym(handle, symbol);
        if (!value || *value != 900 + index) ++*violations;
        atomic_store_explicit(&published, index + 1, memory_order_release);
    }
    atomic_fetch_add(&finished, 1);
    return 0;
}

static char failure_text[1024];

static void *failer(void *argument)
{
    long *mismatches = argument;
    for (int attempt = 0; attempt < FAILURES; ++attempt) {
        if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) { ++*mismatches; continue; }
        const char *error = dlerror();
        if (!error) { ++*mismatches; continue; }
        if (!attempt) snprintf(failure_text, sizeof failure_text, "%s", error);
        else if (strcmp(error, failure_text)) ++*mismatches;
        if (dlerror()) ++*mismatches;
    }
    atomic_fetch_add(&finished, 1);
    return 0;
}

struct scan { long violations; unsigned images; unsigned long long adds; };

static int scan_image(struct dl_phdr_info *info, size_t size, void *data)
{
    struct scan *scan = data;
    (void)size;
    scan->adds = info->dlpi_adds;
    const char *name = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(name, "libfr_")) ++scan->violations;
    if (strstr(name, "libcc_ok")) ++scan->images;
    if (info->dlpi_tls_modid && !info->dlpi_tls_data) ++scan->violations;
    return 0;
}

struct reader_result { long violations; long passes; };

static void reader_pass(struct reader_result *result, unsigned *images, unsigned long long *adds)
{
    int visible = atomic_load_explicit(&published, memory_order_acquire);
    struct scan scan = {0, 0, 0};
    dl_iterate_phdr(scan_image, &scan);
    result->violations += scan.violations;
    if (scan.images < *images || scan.images < (unsigned)visible || scan.adds < *adds) ++result->violations;
    *images = scan.images;
    *adds = scan.adds;
    for (int index = 0; index < visible; ++index) {
        char symbol[32];
        snprintf(symbol, sizeof symbol, "cc_ok_value%d", index);
        int *value = dlsym(RTLD_DEFAULT, symbol);
        if (!value || *value != 900 + index) ++result->violations;
        if (index % 2) {
            snprintf(symbol, sizeof symbol, "cc_ok_tls_read%d", index);
            int (*read)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, symbol);
            if (!read || read() != 800 + index) ++result->violations;
        }
    }
    if (dlsym(RTLD_DEFAULT, "fr_root_value") || dlsym(RTLD_DEFAULT, "fr_tls_value")) ++result->violations;
    const char *error = dlerror();
    if (!error || strcmp(error, "Symbol not found: fr_tls_value")) ++result->violations;
    ++result->passes;
}

static void *reader(void *argument)
{
    struct reader_result *result = argument;
    unsigned images = 0;
    unsigned long long adds = 0;
    do reader_pass(result, &images, &adds);
    while (atomic_load(&finished) != 2);
    reader_pass(result, &images, &adds);
    return 0;
}

static int count_final(struct dl_phdr_info *info, size_t size, void *data)
{
    struct scan *scan = data;
    (void)size;
    scan->adds = info->dlpi_adds;
    if (info->dlpi_name && strstr(info->dlpi_name, "libcc_ok")) ++scan->images;
    if (info->dlpi_name && strstr(info->dlpi_name, "libfr_")) ++scan->violations;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "missing") && strcmp(argv[1], "unresolved"))) return 2;
    struct scan before = {0, 0, 0};
    dl_iterate_phdr(count_final, &before);
    long opener_violations = 0, failer_mismatches = 0;
    struct reader_result results[READERS] = {{0, 0}};
    pthread_t threads[READERS + 2];
    for (int index = 0; index < READERS; ++index)
        if (pthread_create(&threads[index], 0, reader, &results[index])) return 3;
    if (pthread_create(&threads[READERS], 0, opener, &opener_violations)
        || pthread_create(&threads[READERS + 1], 0, failer, &failer_mismatches)) return 3;
    for (int index = 0; index < READERS + 2; ++index)
        if (pthread_join(threads[index], 0)) return 4;

    struct scan after = {0, 0, 0};
    dl_iterate_phdr(count_final, &after);
    printf("opener violations=%ld\n", opener_violations);
    printf("failer mismatches=%ld\n", failer_mismatches);
    print_reduced("failure text", failure_text);
    for (int index = 0; index < READERS; ++index)
        printf("reader %d violations=%ld ran=%d\n", index, results[index].violations, results[index].passes > 0);
    printf("final images=%u rolled back visible=%ld adds delta=%llu\n",
        after.images, after.violations, after.adds - before.adds);
    printf("main pending error: %s\n", dlerror() ? "yes" : "(none)");
    printf("NOLOAD rolled-back tls: %s\n", result(dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD)));
    show_error("NOLOAD rolled-back tls");
    puts("concurrent contract: complete");
    return 0;
}
