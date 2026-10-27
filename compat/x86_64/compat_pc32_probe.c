#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>

int main(void)
{
    void *handle = dlopen("/usr/lib/symbol-pc32.so", RTLD_NOW);
    int32_t *slot = handle ? dlsym(handle, "mutable_function") : 0;
    void *target = handle ? dlsym(handle, "getpid") : 0;
    if (!slot || !target) return 1;
    intptr_t delta = (intptr_t)target - (intptr_t)slot;
    return delta < INT32_MIN || delta > INT32_MAX || *slot != delta
        || access("/symbol-mutable-marker", F_OK) != 0 || dlclose(handle) != 0;
}
