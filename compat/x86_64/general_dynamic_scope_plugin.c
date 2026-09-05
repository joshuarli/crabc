#define _GNU_SOURCE
#include <dlfcn.h>
#ifdef SECOND_PROVIDER
int scope_value = 22;
#else
int scope_value = 11;
int scope_next(void)
{
    int *next = dlsym(RTLD_NEXT, "scope_value");
    return next ? *next : -1;
}
#endif
