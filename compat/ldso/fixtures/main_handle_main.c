#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 10;
    if (dlsym(handle, "main") != (void *)main)
        return 11;
    if (dlclose(handle) != 0)
        return 12;
    puts("main-handle=ok");
    return 0;
}
