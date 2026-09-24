/* Musl differential for fork against runtime-load transactions.
 *
 * `threaded`: a loader thread alternates the failed libfr_root.so graph
 * (general_dynamic_dlfcn_contract_rollback.c, missing mode) with sixteen
 * libcc_ok*.so successes while the main thread forks repeatedly. Pinned musl
 * 1.2.6 src/process/fork.c takes ldso/dynlink.c's loader and init/fini locks
 * through __ldso_atfork, so every child sees a committed graph: no
 * rolled-back object, every listed success resolvable, the same failure
 * text, and working new loads and TLS in a fresh child thread. Only
 * interleaving-independent counts are printed.
 *
 * `constructor`: dlopen(libfk_ctor.so), whose constructor forks. The child
 * runs a failed load, reopens its still-constructing object and loads a new
 * TLS module before exiting; the parent constructor then completes.
 *
 * Usage: consumer threaded|constructor */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "general_dynamic_dlfcn_contract.h"

enum { SUCCESSES = 16, ATTEMPTS = 48, FORKS = 24 };

static atomic_int forks_done;
static long loader_violations;
static char failure_text[1024];

static void *loader(void *argument)
{
    (void)argument;
    int loaded = 0;
    /* Keep loading until every fork has happened, so each fork overlaps. */
    for (int attempt = 0; attempt < ATTEMPTS || !atomic_load(&forks_done); ++attempt) {
        if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) ++loader_violations;
        const char *error = dlerror();
        if (!error || strcmp(error, failure_text)) ++loader_violations;
        if (attempt % 3 == 0 && loaded < SUCCESSES) {
            char name[32];
            snprintf(name, sizeof name, "libcc_ok%d.so", loaded++);
            if (!dlopen(name, RTLD_NOW | RTLD_GLOBAL)) ++loader_violations;
        }
    }
    return 0;
}

struct child_scan { int violations; int images; };

static int child_image(struct dl_phdr_info *info, size_t size, void *data)
{
    struct child_scan *scan = data;
    (void)size;
    const char *name = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(name, "libfr_")) ++scan->violations;
    const char *base = strstr(name, "libcc_ok");
    if (!base) return 0;
    ++scan->images;
    int index = atoi(base + 8);
    char symbol[32];
    snprintf(symbol, sizeof symbol, "cc_ok_value%d", index);
    void *handle = dlopen(base, RTLD_NOW | RTLD_NOLOAD);
    int *value = handle ? dlsym(handle, symbol) : 0;
    if (!value || *value != 900 + index) ++scan->violations;
    return 0;
}

static void *child_thread(void *argument)
{
    int (*read)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "cc_ok_tls_read15");
    *(int *)argument = read ? read() : -1;
    return 0;
}

static int child_checks(void)
{
    struct child_scan scan = {0, 0};
    dl_iterate_phdr(child_image, &scan);
    int violations = scan.violations;
    if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) ++violations;
    const char *error = dlerror();
    if (!error || strcmp(error, failure_text)) ++violations;
    if (!dlopen("libcc_ok15.so", RTLD_NOW | RTLD_GLOBAL)) ++violations;
    int value = 0;
    pthread_t thread;
    if (pthread_create(&thread, 0, child_thread, &value) || pthread_join(thread, 0) || value != 815) ++violations;
    return violations;
}

static int threaded(void)
{
    if (dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)) return 3;
    snprintf(failure_text, sizeof failure_text, "%s", dlerror());
    print_reduced("failure text", failure_text);
    pthread_t thread;
    if (pthread_create(&thread, 0, loader, 0)) return 3;
    int children = 0, failed = 0;
    for (int round = 0; round < FORKS; ++round) {
        fflush(stdout);
        pid_t child = fork();
        if (child < 0) return 4;
        if (child == 0) _exit(child_checks());
        int status = -1;
        if (waitpid(child, &status, 0) != child) return 5;
        ++children;
        if (!WIFEXITED(status) || WEXITSTATUS(status)) ++failed;
    }
    atomic_store(&forks_done, 1);
    pthread_join(thread, 0);
    printf("children=%d failed=%d\n", children, failed);
    printf("loader violations=%ld\n", loader_violations);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) _exit(child_checks());
    int status = -1;
    waitpid(child, &status, 0);
    printf("final child exited=%d status=%d\n", WIFEXITED(status), WEXITSTATUS(status));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "threaded")) {
        int status = threaded();
        if (status) return status;
    } else if (!strcmp(argv[1], "constructor")) {
        void *handle = dlopen("libfk_ctor.so", RTLD_NOW);
        printf("constructor open: %s\n", result(handle));
        show_error("constructor open");
        printf("parent NOLOAD rolled-back tls: %s\n", result(dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD)));
        show_error("parent NOLOAD rolled-back tls");
        printf("parent child-loaded libcc_ok3: %s\n", result(dlopen("libcc_ok3.so", RTLD_NOW | RTLD_NOLOAD)));
        show_error("parent child-loaded libcc_ok3");
    } else {
        return 2;
    }
    puts("fork contract: complete");
    return 0;
}
