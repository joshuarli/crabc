#include <dlfcn.h>
#include <stdio.h>

typedef int (*hash_value_fn)(void);

static int load_value(void *handle, const char *name)
{
    hash_value_fn value = (hash_value_fn)dlsym(handle, name);
    return value == NULL ? -1 : value();
}

int main(void)
{
    void *handle = dlopen("libhash_many.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 10;
    int first = load_value(handle, "hash_many_0");
    int last = load_value(handle, "hash_many_1024");
    if (first != 0 || last != 1024)
        return 11;
    if (dlclose(handle) != 0)
        return 12;
    printf("hash-many=%d,%d\n", last, first);
    return 0;
}
