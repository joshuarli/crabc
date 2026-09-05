#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "runtime rollback failed line %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)
static int count(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)info; (void)size;
    ++*(int *)data;
    return 0;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    void *stable = dlopen("libgrowth0.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(stable);
    int *value = dlsym(stable, "growth_value");
    CHECK(value && *value == 17);
    *value = 91;
    int before = 0, after = 0;
    CHECK(!dl_iterate_phdr(count, &before));
    CHECK(!dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL));
    CHECK(dlerror() && !dlerror());
    CHECK(!dl_iterate_phdr(count, &after) && after == before);
    CHECK(!dlopen(argv[1], RTLD_NOW | RTLD_NOLOAD));
    CHECK(dlerror() && !dlerror());
    CHECK(!dlsym(RTLD_DEFAULT, "failure_address"));
    CHECK(dlerror() && !dlerror());
    CHECK(dlsym(stable, "growth_value") == value && *value == 91);
    /* A failed admission must not poison later mapping or TLS generations. */
    void *next = dlopen("libgrowth1.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(next && *(int *)dlsym(next, "growth_value") == 18);
    CHECK(*value == 91 && !dlclose(next) && !dlclose(stable));
    puts("runtime rollback: unchanged scope, TLS and constructor ownership");
    return 0;
}
