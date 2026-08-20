#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    if (dlopen("libnot-present.so", RTLD_NOW) != NULL)
        return 10;
    if (dlerror() == NULL || dlerror() != NULL)
        return 11;

    void *handle = dlopen("libdlerror.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 12;
    if (dlsym(handle, "not_present") != NULL)
        return 13;
    if (dlerror() == NULL || dlerror() != NULL)
        return 14;
    puts("dlerror=ok");
    return dlclose(handle) == 0 ? 0 : 15;
}
