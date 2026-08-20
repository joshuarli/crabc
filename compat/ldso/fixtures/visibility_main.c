#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("libvisibility.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 10;
    int (*public_value)(void) = (int (*)(void))dlsym(handle, "visibility_public");
    if (public_value == NULL || public_value() != 23 || dlerror() != NULL)
        return 11;
    if (dlsym(handle, "visibility_hidden") != NULL || dlerror() == NULL)
        return 12;
    puts("visibility=ok");
    return dlclose(handle) == 0 ? 0 : 13;
}
