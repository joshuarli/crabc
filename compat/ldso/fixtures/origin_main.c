#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *handle = dlopen("bundle/liborigin_mid.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        return 10;
    }
    int (*origin_mid)(void) = (int (*)(void))dlsym(handle, "origin_mid");
    if (origin_mid == NULL) {
        return 11;
    }
    printf("origin=%d\n", origin_mid());
    return dlclose(handle) == 0 ? 0 : 12;
}
