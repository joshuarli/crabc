#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef GENERATION
#define GENERATION 0
#endif

_Thread_local int growth_value __attribute__((aligned(4096))) = 17 + GENERATION;
static _Thread_local unsigned char growth_zero[73] __attribute__((aligned(64)));
static int constructed;

int *growth_address(void) { return &growth_value; }
int growth_check(void)
{
    if ((uintptr_t)&growth_value % 4096 || (uintptr_t)growth_zero % 64)
        return 1;
    for (unsigned i = 0; i < sizeof growth_zero; ++i)
        if (growth_zero[i]) return 2;
    return 0;
}
int growth_constructed(void) { return constructed; }

static void initialize(void) __attribute__((constructor));
static void initialize(void)
{
    Dl_info info;
    if (++constructed != 1 || growth_check()
        || !dladdr((void *)growth_address, &info)) abort();
    /* Same-thread constructor reentry must acquire the published identity,
       skip its own in-progress callback, and preserve the once-only claim. */
    void *self = dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL);
    if (!self || dlsym(self, "growth_address") != (void *)growth_address
        || dlclose(self)) abort();
#if GENERATION == 40
    /* Widen the concurrent open window without holding application locks. */
    struct timespec delay = {0, 20000000};
    nanosleep(&delay, 0);
#endif
}

static void finalize(void) __attribute__((destructor));
static void finalize(void)
{
    if (constructed != 1) abort();
    printf("runtime fini %d\n", GENERATION);
}
