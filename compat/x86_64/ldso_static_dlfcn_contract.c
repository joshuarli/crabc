/* Musl differential for the dlfcn surface of a static executable
 * (run_ldso_static_dlfcn.sh).
 *
 * Pinned musl 1.2.6 libc.a has no loader: src/ldso/dlopen.c's weak stub
 * fails every open with "Dynamic loading not supported", __dlsym.c's stub
 * reports "Symbol not found: %s", dlerror.c's weak __dl_invalid_handle
 * rejects every handle (so dlclose returns 1 and dlinfo -1), dladdr.c's stub
 * returns 0, and dl_iterate_phdr.c's static body reports exactly the
 * executable from AT_PHDR. Output is the comparison surface; addresses are
 * compared, not printed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

__thread int static_tls_value = 17;

static void show_error(const char *label)
{
    const char *error = dlerror();
    printf("%s: %s\n", label, error ? error : "(none)");
}

static int images;
static int visit(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)data;
    ++images;
    printf("image %d: size-ok=%d name=\"%s\" phdr-is-AT_PHDR=%d phnum-is-AT_PHNUM=%d adds=%llu subs=%llu"
        " tls=%zu tls-data-is-value=%d\n",
        images, size >= sizeof *info, info->dlpi_name ? info->dlpi_name : "(null)",
        (uintptr_t)info->dlpi_phdr == getauxval(AT_PHDR), info->dlpi_phnum == getauxval(AT_PHNUM),
        (unsigned long long)info->dlpi_adds, (unsigned long long)info->dlpi_subs,
        info->dlpi_tls_modid, info->dlpi_tls_data == (void *)&static_tls_value);
    return images == 7 ? 7 : 0;
}
static int stop(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)info; (void)size; (void)data;
    return 42;
}

static void *thread_errors(void *argument)
{
    (void)argument;
    show_error("thread starts");
    printf("thread dlopen: %s\n", dlopen("libthread.so", RTLD_NOW) ? "handle" : "null");
    show_error("thread dlopen");
    return 0;
}

int main(void)
{
    show_error("initial");
    printf("dlopen(NULL): %s\n", dlopen(NULL, RTLD_NOW) ? "handle" : "null");
    show_error("dlopen(NULL)");
    printf("dlopen(name): %s\n", dlopen("libanything.so", RTLD_LAZY | RTLD_NOLOAD) ? "handle" : "null");
    show_error("dlopen(name)");
    printf("dlsym default: %s\n", dlsym(RTLD_DEFAULT, "main") ? "found" : "null");
    show_error("dlsym default");
    printf("dlsym next: %s\n", dlsym(RTLD_NEXT, "printf") ? "found" : "null");
    show_error("dlsym next");
    printf("dlclose NULL: %d\n", dlclose(NULL));
    show_error("dlclose NULL");
    printf("dlclose bogus: %d\n", dlclose((void *)(uintptr_t)0x1230));
    show_error("dlclose bogus");
    struct link_map *map = (void *)(uintptr_t)0xfeed;
    printf("dlinfo: %d unchanged=%d\n", dlinfo((void *)(uintptr_t)0x1230, RTLD_DI_LINKMAP, &map),
        map == (void *)(uintptr_t)0xfeed);
    show_error("dlinfo");
    Dl_info info;
    memset(&info, 0x5a, sizeof info);
    Dl_info untouched = info;
    printf("dladdr main: %d untouched=%d\n", dladdr((void *)main, &info), !memcmp(&info, &untouched, sizeof info));
    show_error("dladdr main");
    /* A later error replaces an unconsumed one; consumption is one-shot. */
    dlopen("first.so", RTLD_NOW);
    dlsym(RTLD_DEFAULT, "second");
    show_error("replaced");
    show_error("consumed");
    dlsym(RTLD_DEFAULT, "main_pending");
    pthread_t thread;
    if (pthread_create(&thread, 0, thread_errors, 0) || pthread_join(thread, 0)) return 1;
    show_error("main after thread");
    int iterated = dl_iterate_phdr(visit, 0);
    printf("iterate: %d images=%d\n", iterated, images);
    printf("iterate stop: %d\n", dl_iterate_phdr(stop, 0));
    puts("static dlfcn contract: complete");
    return 0;
}
