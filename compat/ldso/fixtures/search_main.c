#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("libsearch.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 20;
    int (*value)(void) = (int (*)(void))dlsym(handle, "search_value");
    if (!value)
        return 21;
    printf("search=%d\n", value());
    return dlclose(handle) == 0 ? 0 : 22;
}
