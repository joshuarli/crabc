#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>

static int initialized;
__attribute__((constructor)) static void constructor(void)
{
    /* Reenter the graph only after its ADD transaction became CONSISTENT. */
    void *libc = dlopen("libc.so", RTLD_NOW);
    struct r_debug **slot = libc ? dlsym(libc, "_dl_debug_addr") : 0;
    if (slot && *slot && (*slot)->r_state == RT_CONSISTENT) ++initialized;
    if (libc) dlclose(libc);
}

int loader_debug_plugin_value(void) { return initialized == 1 ? 42 : -1; }
