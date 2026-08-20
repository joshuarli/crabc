#include <dlfcn.h>
#include <stdio.h>

static int load_value(const char *name)
{
    void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return -1;
    int (*value)(void) = (int (*)(void))dlsym(handle, "hash_value");
    if (value == NULL)
        return -2;
    int result = value();
    return dlclose(handle) == 0 ? result : -3;
}

int main(void)
{
    int gnu = load_value("libhash_gnu.so");
    int sysv = load_value("libhash_sysv.so");
    if (gnu < 0 || sysv < 0)
        return 10;
    printf("hash=%d,%d\n", gnu, sysv);
    return 0;
}
