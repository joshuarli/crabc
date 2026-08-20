#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("libaslr.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 40;
    int (*value)(void) = (int (*)(void))dlsym(handle, "aslr_value");
    if (!value)
        return 41;
    Dl_info info = {0};
    if (!dladdr((const void *)value, &info) || !info.dli_fbase)
        return 42;
    Dl_info main_info = {0};
    if (!dladdr((const void *)&main, &main_info) || !main_info.dli_fbase)
        return 43;
    printf("aslr=%d main=%p dso=%p\n", value(), main_info.dli_fbase, info.dli_fbase);
    return dlclose(handle) == 0 ? 0 : 44;
}
