/* Musl differential for failed multi-object dlopen rollback.
 *
 * libfr_root.so needs libfr_tls.so (a TLS module) and then libfr_late.so.
 * The first open maps the TLS dependency and fails on the later one: in
 * `missing` mode libfr_late.so is absent; in `unresolved` mode it lacks the
 * data symbol libfr_root.so relocates against. Pinned musl 1.2.6
 * ldso/dynlink.c::dlopen longjmps to its rtld_fail cleanup, which unmaps
 * every object after the original tail and restores the TLS count, so no
 * constructor runs, no image is published and dlpi_adds is unchanged. After
 * the complete libfr_late.so is renamed into place the same request
 * succeeds, and a thread that existed across the failure observes the new
 * TLS module. Output is the comparison surface.
 *
 * Usage: consumer LIBRARY_DIRECTORY missing|unresolved */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "general_dynamic_dlfcn_contract.h"

struct images { unsigned count; unsigned long long adds; };

static int count_images(struct dl_phdr_info *info, size_t size, void *data)
{
    struct images *images = data;
    (void)size;
    images->adds = info->dlpi_adds;
    if (info->dlpi_name && strstr(info->dlpi_name, "libfr_")) {
        printf("  image %s\n", base_name(info->dlpi_name));
        images->count++;
    }
    return 0;
}

static struct images snapshot(const char *label)
{
    struct images images = {0, 0};
    printf("%s images:\n", label);
    dl_iterate_phdr(count_images, &images);
    printf("%s image count=%u\n", label, images.count);
    return images;
}

static pthread_barrier_t barrier;
static int *(*worker_address)(void);
struct worker_view { int value; int *address; };

/* Exists across the failed and successful loads; reads the new module only
 * after the retry commits. Its block ends with the thread, so it reports the
 * value rather than a pointer into that block. */
static void *worker(void *argument)
{
    struct worker_view *view = argument;
    pthread_barrier_wait(&barrier);
    pthread_barrier_wait(&barrier);
    view->address = worker_address();
    view->value = *view->address;
    pthread_barrier_wait(&barrier);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[2], "missing") && strcmp(argv[2], "unresolved"))) return 2;
    struct worker_view view = { -1, 0 };
    pthread_t thread;
    if (pthread_barrier_init(&barrier, 0, 2) || pthread_create(&thread, 0, worker, &view)) return 3;
    pthread_barrier_wait(&barrier);

    struct images before = snapshot("before");
    printf("failed open: %s\n", result(dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)));
    show_error("failed open");
    struct images after = snapshot("after failure");
    printf("after failure: count unchanged=%d adds delta=%llu\n",
        after.count == before.count, after.adds - before.adds);
    printf("NOLOAD root: %s\n", result(dlopen("libfr_root.so", RTLD_NOW | RTLD_NOLOAD)));
    show_error("NOLOAD root");
    printf("NOLOAD tls dependency: %s\n", result(dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD)));
    show_error("NOLOAD tls dependency");
    printf("default fr_tls_value: %s\n", dlsym(RTLD_DEFAULT, "fr_tls_value") ? "found" : "null");
    show_error("default fr_tls_value");
    printf("default fr_root_value: %s\n", dlsym(RTLD_DEFAULT, "fr_root_value") ? "found" : "null");
    show_error("default fr_root_value");

    /* Repeating the same failure is equally transactional. */
    printf("repeated failure: %s\n", result(dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)));
    show_error("repeated failure");
    after = snapshot("after repeat");
    printf("after repeat: adds delta=%llu\n", after.adds - before.adds);

    char staged[512], installed[512];
    snprintf(staged, sizeof staged, "%s/libfr_late.so.next", argv[1]);
    snprintf(installed, sizeof installed, "%s/libfr_late.so", argv[1]);
    if (rename(staged, installed)) return 4;
    fflush(stdout);
    void *root = dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL);
    printf("retry: %s\n", result(root));
    if (!root) {
        show_error("retry");
        return 5;
    }
    struct images retried = snapshot("after retry");
    printf("after retry: adds delta=%llu\n", retried.adds - before.adds);
    int (*root_value)(void) = (int (*)(void))dlsym(root, "fr_root_value");
    printf("fr_root_value=%d\n", root_value ? root_value() : -1);
    int *(*address)(void) = (int *(*)(void))dlsym(RTLD_DEFAULT, "fr_tls_address");
    int *value = dlsym(RTLD_DEFAULT, "fr_tls_value");
    printf("main tls: %d dlsym matches=%d\n", address ? *address() : -1, address && value == address());
    if (!address) return 6;
    worker_address = address;
    pthread_barrier_wait(&barrier);
    pthread_barrier_wait(&barrier);
    printf("existing worker tls: %d distinct=%d\n", view.value, view.address && view.address != address());
    pthread_join(thread, 0);
    printf("NOLOAD tls after retry: %d\n", dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD) != 0);
    puts("rollback contract: complete");
    return 0;
}
