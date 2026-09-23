#define _GNU_SOURCE
#include "general_dynamic_constructor_barrier_state.h"
#include <dlfcn.h>
#include <link.h>
#include <sched.h>
#include <time.h>

int constructor_barrier_value(void) { return 73; }

static int count_self(struct dl_phdr_info *info, size_t size, void *argument)
{
    (void)size;
    if (info->dlpi_name && __builtin_strstr(info->dlpi_name, "libconstructor-barrier.so"))
        ++*(int *)argument;
    return 0;
}

__attribute__((constructor)) static void hold_constructor_for_foreign_reads(void)
{
    constructor_barrier_entered();

    /* Same-thread reads stay available during constructor execution. */
    void *lookup = dlsym(RTLD_DEFAULT, "constructor_barrier_value");
    if (lookup != (void *)constructor_barrier_value)
        constructor_barrier_early_completion(-1);
    int self_count = 0;
    dl_iterate_phdr(count_self, &self_count);
    if (self_count != 1)
        constructor_barrier_early_completion(-1);

    /* Wait until both foreign calls are at their entry points, then hold the
     * constructor open long enough to observe whether they complete early. */
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
    for (unsigned index = 0; index < 5000 && constructor_barrier_attempts() != 2; ++index)
        nanosleep(&pause, 0);
    if (constructor_barrier_attempts() != 2) {
        constructor_barrier_early_completion(-1);
        return;
    }
    for (unsigned index = 0; index < 100; ++index)
        nanosleep(&pause, 0);
    constructor_barrier_early_completion(constructor_barrier_completed());
}
