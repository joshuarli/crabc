#define _GNU_SOURCE
#include <dlfcn.h>
#ifdef SECOND_PROVIDER
int scope_value = 22;
int scope_hidden_value(void) { return 44; }
#else
int scope_value = 11;
int scope_next(void)
{
    int *next = dlsym(RTLD_NEXT, "scope_value");
    return next ? *next : -1;
}
int scope_next_hidden(void)
{
    int (*next)(void) = dlsym(RTLD_NEXT, "scope_hidden_value");
    return next ? next() : -1;
}
#endif
