#include <dlfcn.h>
#include <unistd.h>

int main(void)
{
    void *handle = dlopen("/usr/lib/symbol-mutable.so", RTLD_NOW);
    int (*mutate)(void) = handle ? (int (*)(void))dlsym(handle, "symbol_mutate") : 0;
    return !mutate || !mutate() || access("/symbol-mutable-marker", F_OK) != 0 || dlclose(handle) != 0;
}
