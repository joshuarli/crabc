#include <dlfcn.h>

int main(void)
{
    void *tls = dlopen("/usr/lib/tls-mutable.so", RTLD_NOW);
    if (!tls) return 1;
    int *(*address)(void) = (int *(*)(void))dlsym(tls, "hardened_tls_address");
    long (*value)(void) = (long (*)(void))dlsym(tls, "hardened_tls_mutable_value");
    int (*mutate)(void) = (int (*)(void))dlsym(tls, "hardened_tls_mutate");
    return !address || !value || !mutate || *address() != 7 || value() != 0
        || !mutate() || value() != 42 || *address() != 7 || dlclose(tls) != 0;
}
