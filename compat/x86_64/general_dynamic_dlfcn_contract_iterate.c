/* Musl differential for dlfcn reentry from dl_iterate_phdr callbacks while
 * another thread loads.
 *
 * A loader thread publishes libcc_ok0..15.so as RTLD_GLOBAL. Meanwhile the
 * main thread repeatedly iterates; its callback reopens and closes every
 * visited libcc_ok image, closes the object being visited, runs the failed
 * libfr_root.so graph (general_dynamic_dlfcn_contract_rollback.c, missing
 * mode) and, once per pass, loads its own libcc_ok image. Pinned musl 1.2.6
 * ldso/dynlink.c::dl_iterate_phdr calls back without its lock and reads the
 * successor afterwards, and dlclose retains objects, so traversal survives
 * each nested operation, never visits a rolled-back object and dlpi_adds
 * never decreases. Only interleaving-independent counts are printed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "general_dynamic_dlfcn_contract.h"

enum { SUCCESSES = 16 };

static atomic_int loader_done;
static char failure_text[1024];

static void *loader(void *argument)
{
    long *violations = argument;
    for (int index = 0; index < SUCCESSES; index += 2) {
        char name[32];
        snprintf(name, sizeof name, "libcc_ok%d.so", index);
        if (!dlopen(name, RTLD_NOW | RTLD_GLOBAL)) ++*violations;
    }
    atomic_store(&loader_done, 1);
    return 0;
}

struct pass { long violations; int visited; int nested; unsigned long long adds; };
static int next_nested = 1;

static int visit(struct dl_phdr_info *info, size_t size, void *data)
{
    struct pass *pass = data;
    (void)size;
    if (info->dlpi_adds < pass->adds) ++pass->violations;
    pass->adds = info->dlpi_adds;
    const char *name = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(name, "libfr_")) ++pass->violations;
    const char *base = strstr(name, "libcc_ok");
    if (base) {
        ++pass->visited;
        void *handle = dlopen(base, RTLD_NOW | RTLD_NOLOAD);
        if (!handle || dlclose(handle) || dlclose(handle)) ++pass->violations;
        int index = atoi(base + 8);
        char symbol[32];
        snprintf(symbol, sizeof symbol, "cc_ok_value%d", index);
        int *value = dlsym(RTLD_DEFAULT, symbol);
        if (!value || *value != 900 + index) ++pass->violations;
    }
    if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) ++pass->violations;
    const char *error = dlerror();
    if (!error || strcmp(error, failure_text)) ++pass->violations;
    if (!pass->nested && next_nested < SUCCESSES) {
        char nested[32];
        snprintf(nested, sizeof nested, "libcc_ok%d.so", next_nested);
        next_nested += 2;
        pass->nested = 1;
        if (!dlopen(nested, RTLD_NOW | RTLD_GLOBAL)) ++pass->violations;
    }
    return 0;
}

static int count_final(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    if (info->dlpi_name && strstr(info->dlpi_name, "libcc_ok")) ++*(int *)data;
    return 0;
}

int main(void)
{
    if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) return 3;
    snprintf(failure_text, sizeof failure_text, "%s", dlerror());
    print_reduced("failure text", failure_text);
    long loader_violations = 0, violations = 0;
    int passes = 0;
    pthread_t thread;
    if (pthread_create(&thread, 0, loader, &loader_violations)) return 3;
    do {
        struct pass pass = {0, 0, 0, 0};
        if (dl_iterate_phdr(visit, &pass)) ++violations;
        violations += pass.violations;
        ++passes;
    } while (!atomic_load(&loader_done) || next_nested < SUCCESSES);
    pthread_join(thread, 0);
    int images = 0;
    dl_iterate_phdr(count_final, &images);
    printf("loader violations=%ld callback violations=%ld ran=%d\n", loader_violations, violations, passes > 0);
    printf("final images=%d\n", images);
    printf("NOLOAD rolled-back tls: %s\n", result(dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD)));
    show_error("NOLOAD rolled-back tls");
    puts("iterate contract: complete");
    return 0;
}
