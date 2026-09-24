/* Musl differential for the selected public dlfcn contract over a general
 * graph: main -> libdc_init.so -> libdc_base.so initially, then the
 * runtime-new libdc_rt.so -> {libdc_rtdep.so, libdc_base.so} closure.
 *
 * Output is the comparison surface. It deliberately omits link layout and
 * load addresses, reduces absolute paths to basenames, and lists only this
 * fixture's application objects: the owned interpreter is a separate image,
 * while musl's loader is libc itself. Pinned musl 1.2.6 sources of the
 * observed behavior are ldso/dynlink.c::{dlopen,load_library,load_deps,
 * do_relocs,queue_ctors,__dl_invalid_handle,do_dlsym,dladdr,dl_iterate_phdr}
 * and src/ldso/{dlclose,dlinfo,dlerror}.c. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#include "general_dynamic_dlfcn_contract.h"

extern int dc_init_next_shared(void);

static const char *main_name(const char *name)
{
    const char *executable = (const char *)getauxval(AT_EXECFN);
    if (!name) return "null";
    if (!*name) return "empty";
    return executable && !strcmp(name, executable) ? "AT_EXECFN" : name;
}

static int list_objects(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)data;
    if (size < sizeof *info) return 1;
    const char *tls = info->dlpi_tls_modid ? (info->dlpi_tls_data ? "data" : "null") : "none";
    if ((uintptr_t)info->dlpi_phdr == getauxval(AT_PHDR))
        printf("iterate main: name=%s subs=%llu tls=%s\n", main_name(info->dlpi_name),
            (unsigned long long)info->dlpi_subs, tls);
    else if (strstr(info->dlpi_name, "libdc_"))
        printf("iterate %s: subs=%llu tls=%s\n", base_name(info->dlpi_name),
            (unsigned long long)info->dlpi_subs, tls);
    return 0;
}

static unsigned long long additions;
static int record_additions(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    additions = info->dlpi_adds;
    return 1;
}

static void *thread_error(void *argument)
{
    (void)argument;
    printf("thread starts with: %s\n", dlerror() ? "a pending error" : "(none)");
    dlsym(RTLD_DEFAULT, "dc_thread_missing");
    show_error("thread own error");
    return 0;
}

int main(void)
{
    int *value;
    /* Initial global scope, weak-first lookup, RTLD_NEXT and the main handle. */
    value = dlsym(RTLD_DEFAULT, "dc_shared");
    printf("default dc_shared=%d\n", value ? *value : -1);
    value = dlsym(RTLD_DEFAULT, "dc_weak");
    printf("default dc_weak=%d\n", value ? *value : -1);
    value = dlsym(RTLD_NEXT, "dc_shared");
    printf("main RTLD_NEXT dc_shared=%d\n", value ? *value : -1);
    printf("init RTLD_NEXT dc_shared=%d\n", dc_init_next_shared());
    void *self = dlopen(NULL, RTLD_NOW);
    printf("dlopen(NULL) stable: %d\n", self && self == dlopen(NULL, RTLD_LAZY));
    value = dlsym(self, "dc_base_only");
    printf("main handle dc_base_only=%d\n", value ? *value : -1);
    void *init = dlopen("libdc_init.so", RTLD_NOW | RTLD_NOLOAD);
    printf("initial NOLOAD: %s\n", init ? "handle" : "null");
    value = init ? dlsym(init, "dc_shared") : 0;
    printf("init handle dc_shared=%d\n", value ? *value : -1);
    value = init ? dlsym(init, "dc_base_only") : 0;
    printf("init handle dc_base_only=%d\n", value ? *value : -1);

    /* Musl's exact diagnostics for failed opens, lookups and handles. The
     * invalid handles are fixed values, so their %p text is comparable. */
    dlerror();
    printf("missing: %s\n", result(dlopen("libdc_nonexistent.so", RTLD_NOW)));
    show_error("missing");
    printf("NOLOAD unloaded: %s\n", result(dlopen("libdc_rt.so", RTLD_NOW | RTLD_NOLOAD)));
    show_error("NOLOAD unloaded");
    printf("NOLOAD missing: %s\n", result(dlopen("libdc_nonexistent.so", RTLD_LAZY | RTLD_NOLOAD)));
    show_error("NOLOAD missing");
    printf("empty name: %s\n", result(dlopen("", RTLD_NOW)));
    show_error("empty name");
    printf("directory: %s\n", result(dlopen("/", RTLD_NOW)));
    show_error("directory");
    printf("not ELF: %s\n", result(dlopen("libdc_notelf.so", RTLD_NOW)));
    show_error("not ELF");
    printf("missing dependency: %s\n", result(dlopen("libdc_missing.so", RTLD_NOW)));
    show_error("missing dependency");
    printf("unresolved symbol: %s\n", result(dlopen("libdc_unresolved.so", RTLD_NOW)));
    show_error("unresolved symbol");
    printf("runtime initial-exec: %s\n", result(dlopen("libdc_ie.so", RTLD_NOW)));
    show_error("runtime initial-exec");
    printf("relocation type: %s\n", result(dlopen("libdc_badtype.so", RTLD_NOW)));
    show_error("relocation type");
    printf("absent symbol: %s\n", result(dlsym(RTLD_DEFAULT, "dc_nonexistent")));
    show_error("absent symbol");
    void *bogus = (void *)(uintptr_t)0x1230;
    printf("dlclose invalid: %d\n", dlclose(bogus));
    show_error("dlclose invalid");
    printf("dlclose null: %d\n", dlclose(NULL));
    show_error("dlclose null");
    printf("dlsym invalid: %s\n", result(dlsym(bogus, "dc_shared")));
    show_error("dlsym invalid");
    struct link_map *map = (struct link_map *)(uintptr_t)0xfeed;
    printf("dlinfo invalid: %d unchanged=%d\n", dlinfo(bogus, -7, &map), map == (void *)(uintptr_t)0xfeed);
    show_error("dlinfo invalid");
    printf("dlinfo request: %d unchanged=%d\n", dlinfo(self, 99, &map), map == (void *)(uintptr_t)0xfeed);
    show_error("dlinfo request");

    /* A later success does not clear a pending error; each thread owns one. */
    dlsym(RTLD_DEFAULT, "dc_pending");
    dlopen(NULL, RTLD_NOW);
    dlsym(RTLD_DEFAULT, "dc_shared");
    show_error("pending after success");
    show_error("consumed");
    dlsym(RTLD_DEFAULT, "dc_main_pending");
    pthread_t thread;
    if (pthread_create(&thread, 0, thread_error, 0) || pthread_join(thread, 0)) return 1;
    show_error("main after thread");

    /* Musl interprets only LAZY/NOLOAD/GLOBAL; other mode bits are inert. */
    dl_iterate_phdr(record_additions, 0);
    unsigned long long before = additions;
    void *rt = dlopen("libdc_rt.so", 0);
    printf("mode zero: %s\n", rt ? "handle" : "null");
    if (!rt) show_error("mode zero");
    void *again = dlopen("libdc_rt.so", RTLD_LAZY | RTLD_NOW | 0x80000);
    printf("unknown mode bits: %s\n", again == rt ? "same handle" : again ? "other handle" : "null");
    if (!again) show_error("unknown mode bits");
    dl_iterate_phdr(record_additions, 0);
    printf("dlpi_adds per successful dlopen: %llu\n", additions - before);
    if (!rt) return 2;

    /* Handle scope: self then breadth-first dependencies, never globals. */
    value = dlsym(rt, "dc_shared");
    printf("rt handle dc_shared=%d\n", value ? *value : -1);
    value = dlsym(rt, "dc_base_only");
    printf("rt handle dc_base_only=%d\n", value ? *value : -1);
    value = dlsym(rt, "dc_rtdep_only");
    printf("rt handle dc_rtdep_only=%d\n", value ? *value : -1);
    value = dlsym(rt, "dc_init_only");
    printf("rt handle dc_init_only=%d\n", value ? *value : -1);
    show_error("rt handle dc_init_only");
    printf("rt hidden: %s\n", dlsym(rt, "dc_rt_hidden") ? "found" : "null");
    show_error("rt hidden");
    value = dlsym(RTLD_DEFAULT, "dc_rt_only");
    printf("local rt in default scope=%d\n", value ? *value : -1);
    show_error("local rt in default scope");
    int *(*tls_address)(void) = (int *(*)(void))dlsym(rt, "dc_rt_tls_address");
    printf("dlsym TLS is this thread's: %d\n", tls_address && dlsym(rt, "dc_rt_tls") == tls_address());
    printf("NOLOAD|GLOBAL promotion: %d\n", dlopen("libdc_rt.so", RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL) == rt);
    value = dlsym(RTLD_DEFAULT, "dc_rt_only");
    printf("promoted rt in default scope=%d\n", value ? *value : -1);

    /* dladdr: exact and interior symbols, the ELF header page, main, none. */
    Dl_info info;
    void *function = dlsym(rt, "dc_rt_function");
    memset(&info, 0x5a, sizeof info);
    int found = dladdr(function, &info);
    printf("dladdr function: %d %s %s exact=%d\n", found, base_name(info.dli_fname),
        info.dli_sname ? info.dli_sname : "(null)", info.dli_saddr == function);
    int *sized = dlsym(rt, "dc_rt_sized");
    found = dladdr(sized + 3, &info);
    printf("dladdr interior: %d %s start=%d\n", found, info.dli_sname ? info.dli_sname : "(null)",
        info.dli_saddr == (void *)sized);
    void *header = info.dli_fbase;
    found = dladdr(header, &info);
    printf("dladdr ELF header: %d %s base=%d %s saddr=%s\n", found, base_name(info.dli_fname),
        info.dli_fbase == header, info.dli_sname ? info.dli_sname : "(null)", result(info.dli_saddr));
    memset(&info, 0x5a, sizeof info);
    found = dladdr((void *)main, &info);
    printf("dladdr main: %d %s\n", found, main_name(info.dli_fname));
    found = dladdr((void *)(uintptr_t)16, &info);
    printf("dladdr unmapped: %d\n", found);
    show_error("dladdr unmapped");
    found = dladdr(function, &info);
    printf("reopen by dli_fname: %d\n", dlopen(info.dli_fname, RTLD_NOW) == rt);

    /* dlinfo returns the handle's own link map, chained in dso order. */
    map = 0;
    void *(*dynamic)(void) = (void *(*)(void))dlsym(rt, "dc_rt_dynamic");
    found = dlinfo(rt, RTLD_DI_LINKMAP, &map);
    printf("dlinfo: %d map==handle=%d name=%s l_ld=%d\n", found, (void *)map == rt,
        map ? base_name(map->l_name) : "-", map && dynamic && (void *)map->l_ld == dynamic());
    while (map && map->l_prev) map = map->l_prev;
    printf("link map head: %s\n", map ? main_name(map->l_name) : "none");
    for (; map; map = map->l_next)
        if (strstr(map->l_name, "libdc_")) printf("link map: %s\n", base_name(map->l_name));
    dl_iterate_phdr(list_objects, 0);
    printf("dlclose valid: %d %d\n", dlclose(rt), dlclose(rt));
    printf("retained after close: %d\n", dlopen("libdc_rt.so", RTLD_NOW | RTLD_NOLOAD) == rt);
    puts("dlfcn contract: complete");
    fflush(stdout);
    return 0;
}
