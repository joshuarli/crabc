#include <dlfcn.h>
#include <stdio.h>

static int initialized;
__attribute__((constructor)) static void constructor(void) { ++initialized; }

int main(void)
{
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) return 20;
    void (*init)(void) = (void (*)(void))dlsym(libc, "_init");
    void (*fini)(void) = (void (*)(void))dlsym(libc, "_fini");
    if (!init || !fini) return 21;
    init();
    fini();
    if (initialized != 1 || dlclose(libc)) return 22;
    puts("loader-crt-abi-ok");
    return 0;
}
