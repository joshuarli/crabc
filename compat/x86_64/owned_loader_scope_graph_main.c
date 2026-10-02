#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EXTRA_ROOTS 96
static void *extra_handles[MAX_EXTRA_ROOTS];

static int count_object(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)info;
    (void)size;
    ++*(int *)data;
    return 0;
}

static int object_count(void)
{
    int count = 0;
    if (dl_iterate_phdr(count_object, &count) != 0) return -1;
    return count;
}

static int value(void *handle)
{
    int (*get)(void) = (int (*)(void))dlsym(handle, "graph_value");
    return get ? get() : -1;
}

int main(int argc, char **argv)
{
    int ordinary = argc == 4 && strcmp(argv[3], "--ordinary-only") == 0;
    int extra = argc == 3 || ordinary ? atoi(argv[1]) : -1;
    if (extra < 1 || extra > MAX_EXTRA_ROOTS) return 19;
    int initial = object_count();
    if (initial < 1) return 1;

    /* A failed graph must release every new dependency before another root
       tries to load the same names. */
    if (dlopen("libgraph-bad.so", RTLD_NOW | RTLD_LOCAL) != NULL) return 2;
    if (object_count() != initial) return 3;
    if (!ordinary) {
        if (dlopen("libgraph-malformed.so", RTLD_NOW | RTLD_LOCAL) != NULL) return 4;
        if (object_count() != initial) return 5;
    }

    void *ab = dlopen("libgraph-ab.so", RTLD_NOW | RTLD_LOCAL);
    void *ba = dlopen("libgraph-ba.so", RTLD_NOW | RTLD_LOCAL);
    if (!ab || !ba || ab == ba) return 6;
    if (dlopen(argv[2], RTLD_NOW | RTLD_LOCAL) != ab) return 26;
    if (value(ab) != 11 || value(ba) != 22) return 7;
    if (dlsym(RTLD_DEFAULT, "graph_value") != NULL) return 8;

    void (*advance)(void) = (void (*)(void))dlsym(ab, "graph_advance");
    if (!advance) return 9;
    advance();
    if (value(ab) != 12 || value(ba) != 22) return 10;
    if (dlclose(ab) || dlclose(ba)) return 11;
    if (object_count() <= initial) return 12;
    if (dlopen("libgraph-ab.so", RTLD_NOW | RTLD_LOCAL) != ab) return 13;
    if (dlopen("libgraph-ba.so", RTLD_NOW | RTLD_GLOBAL) != ba) return 14;
    if (value(ab) != 12 || value(ba) != 22) return 15;
    if (value(RTLD_DEFAULT) != 22) return 16;
    if (dlopen("libgraph-ab.so", RTLD_NOW | RTLD_GLOBAL) != ab) return 17;
    if (value(RTLD_DEFAULT) != 22 || value(ab) != 12) return 18;

    for (int index = 0; index < extra; ++index) {
        char name[32];
        if (snprintf(name, sizeof name, "libgraph-%02d.so", index) <= 0) return 20;
        void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
        if (!handle || value(handle) != (index % 2 ? 22 : 12)) return 21;
        extra_handles[index] = handle;
        if (dlclose(handle)) return 22;
        if (dlopen(name, RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != handle) return 23;
    }
    for (int index = extra - 1; index >= 0; --index) {
        if (value(extra_handles[index]) != (index % 2 ? 22 : 12)) return 24;
    }
    if (value(RTLD_DEFAULT) != 22) return 25;

    puts("scope graph: rollback, breadth-first handles, retained state, promotion");
    return 0;
}
