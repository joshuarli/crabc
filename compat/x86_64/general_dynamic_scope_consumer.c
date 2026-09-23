#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int begins_with(const char *text, const char *prefix)
{
    return text && strncmp(text, prefix, strlen(prefix)) == 0;
}

int main(void)
{
    void *first = dlopen("libscope-first.so", RTLD_NOW | RTLD_LOCAL);
    void *second = dlopen("libscope-second.so", RTLD_NOW | RTLD_GLOBAL);
    if (!first || !second) return 1;
    int (*next)(void) = (int (*)(void))dlsym(first, "scope_next");
    if (!next || next() != 22) return 2;
    if (*(int *)dlsym(first, "scope_value") != 11
        || *(int *)dlsym(RTLD_DEFAULT, "scope_value") != 22) return 3;
    if (dlopen("libscope-first.so", RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL) != first) return 4;
    if (*(int *)dlsym(RTLD_DEFAULT, "scope_value") != 22 || next() != 22) return 5;
    void *main = dlopen(0, RTLD_NOW);
    if (!main || dlsym(main, "scope_value") != dlsym(RTLD_DEFAULT, "scope_value")) return 6;
    if (dlclose(first) || dlclose(second) || dlclose(main)) return 7;

    /* musl validates the handle before interpreting the request code. */
    void *map = (void *)(uintptr_t)0xfeed;
    dlerror();
    if (dlinfo((void *)(uintptr_t)0x1234, -7, &map) != -1 || map != (void *)(uintptr_t)0xfeed)
        return 8;
    const char *error = dlerror();
    if (!begins_with(error, "Invalid library handle") || dlerror() != NULL) return 9;

    puts("runtime scope: local handles, caller RTLD_NEXT, ordered global promotion");
    return 0;
}
