#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("libnested_mid.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 10;
    int (*value)(void) = (int (*)(void))dlsym(handle, "nested_mid_value");
    if (!value)
        return 11;
    printf("nested-dlopen=%d\n", value());
    return dlclose(handle) == 0 ? 0 : 12;
}
