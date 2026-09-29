#include <stdint.h>

static int constructors;
static int destructors;
static _Thread_local int initialized_tls = 17;
static _Thread_local int zero_tls;

__attribute__((constructor)) static void initialize(void)
{
    ++constructors;
}

__attribute__((destructor)) static void finalize(void)
{
    ++destructors;
}

int loader_iterate_close_race_state(int *constructor_count, int *destructor_count,
                                    int *initialized, int *zero)
{
    *constructor_count = constructors;
    *destructor_count = destructors;
    *initialized = initialized_tls;
    *zero = zero_tls;
    return 0x51ac;
}

void loader_iterate_close_race_set_tls(int initialized, int zero)
{
    initialized_tls = initialized;
    zero_tls = zero;
}
