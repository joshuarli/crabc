#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("liblifecycle.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 30;
    int (*value)(void) = (int (*)(void))dlsym(handle, "lifecycle_value");
    if (!value)
        return 31;
    printf("lifecycle=%d\n", value());
    if (dlclose(handle) != 0)
        return 32;
    printf("after-close\n");
    handle = dlopen("liblifecycle.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 33;
    value = (int (*)(void))dlsym(handle, "lifecycle_value");
    if (!value)
        return 34;
    printf("reopened=%d\n", value());
    if (dlclose(handle) != 0)
        return 35;
    return 0;
}
