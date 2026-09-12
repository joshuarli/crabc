#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern ElfW(Dyn) _DYNAMIC[];
#ifdef DEBUG_COPY_REFERENCE
extern struct r_debug *_dl_debug_addr;
#endif

static int check_debug(void)
{
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) return 10;
    struct r_debug **slot = dlsym(libc, "_dl_debug_addr");
    void (*hook)(void) = (void (*)(void))dlsym(libc, "_dl_debug_state");
    if (!slot || !*slot || !hook) return 11;
    struct r_debug *debug = *slot;
#ifdef DEBUG_COPY_REFERENCE
    if (_dl_debug_addr != debug) return 19;
#endif
    if (debug->r_version != 1 || debug->r_state != RT_CONSISTENT
        || !debug->r_map || !debug->r_brk || !debug->r_ldbase) return 12;
    struct r_debug *dynamic_debug = 0;
    for (ElfW(Dyn) *entry = _DYNAMIC; entry->d_tag; ++entry)
        if (entry->d_tag == DT_DEBUG) dynamic_debug = (void *)entry->d_un.d_ptr;
    if (dynamic_debug != debug) return 13;
    struct link_map *main_map = 0;
    void *main = dlopen(0, RTLD_NOW);
    if (!main || dlinfo(main, RTLD_DI_LINKMAP, &main_map) || main_map != debug->r_map)
        return 14;
    struct link_map *libc_map = 0;
    if (dlinfo(libc, RTLD_DI_LINKMAP, &libc_map)) return 15;
    struct link_map *previous = 0;
    unsigned count = 0;
    int saw_libc = 0;
    for (struct link_map *map = debug->r_map; map; map = map->l_next) {
        if (++count > 256 || map->l_prev != previous || !map->l_name || !map->l_ld)
            return 15;
        if (map == libc_map) saw_libc = 1;
        previous = map;
    }
    if (count < 2 || !saw_libc) return 16;
    /* musl's libc view is also its breakpoint. Exclude this deliberate
     * application call only while tracing actual loader notifications. */
    if (!getenv("CRABC_DEBUGGER_TRACE")) hook();
    if (*slot != debug || debug->r_state != RT_CONSISTENT) return 17;
    if (dlclose(main) || dlclose(libc)) return 18;
    return 0;
}

static int constructor_status;
__attribute__((constructor)) static void constructor(void)
{
    constructor_status = check_debug();
}

int main(int argc, char **argv)
{
    (void)argv;
    if (constructor_status) return constructor_status;
    int status = check_debug();
    if (status) return status;
    void *plugin = dlopen("libloader-debug-plugin.so", RTLD_NOW);
    if (!plugin) return 30;
    int (*value)(void) = (int (*)(void))dlsym(plugin, "loader_debug_plugin_value");
    if (!value || value() != 42 || check_debug()) return 31;
    if (dlopen("libloader-debug-missing.so", RTLD_NOW) || !dlerror() || check_debug())
        return 32;
    if (dlclose(plugin) || value() != 42) return 33;
    void *again = dlopen("libloader-debug-plugin.so", RTLD_NOW);
    if (again != plugin || value() != 42 || dlclose(again)) return 34;
    /* The separate breakpoint observer follows one task. Ordinary runs also
     * prove that fork inherits a CONSISTENT rendezvous and usable locks. */
    if (argc == 1) {
        pid_t child = fork();
        if (child < 0) return 35;
        if (!child) _exit(check_debug());
        int child_status;
        if (waitpid(child, &child_status, 0) != child || child_status) return 36;
    }
    puts("loader-debug-abi-ok");
    return 0;
}
