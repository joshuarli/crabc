#include <dlfcn.h>
#include <unistd.h>

int main(void)
{
    void *handle = dlopen("liblegacy_lifecycle.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 10;
    int (*value)(void) = (int (*)(void))dlsym(handle, "legacy_value");
    if (value == NULL || value() != 37)
        return 11;
    if (write(1, "legacy-value\n", sizeof("legacy-value\n") - 1) < 0)
        return 12;
    return dlclose(handle) == 0 ? 0 : 13;
}
