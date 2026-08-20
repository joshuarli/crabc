#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *local = dlopen("libscope_local.so", RTLD_NOW | RTLD_LOCAL);
    if (local == NULL)
        return 10;
    int (*local_value)(void) = (int (*)(void))dlsym(local, "local_scope_value");
    if (local_value == NULL || local_value() != 21)
        return 11;
    if (dlsym(RTLD_DEFAULT, "local_scope_value") != NULL || dlerror() == NULL)
        return 12;

    void *global = dlopen("libscope_global.so", RTLD_NOW | RTLD_GLOBAL);
    if (global == NULL)
        return 13;
    int (*global_value)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "global_scope_value");
    if (global_value == NULL || global_value() != 34 || dlerror() != NULL)
        return 14;
    printf("scope=%d,%d\n", local_value(), global_value());
    return 0;
}
