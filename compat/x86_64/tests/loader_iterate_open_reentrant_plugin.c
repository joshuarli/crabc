#ifndef PLUGIN_TAG
#error PLUGIN_TAG must identify this DSO
#endif

static int constructors;
static int destructors;
static _Thread_local int initialized_tls = PLUGIN_TAG * 10 + 7;
static _Thread_local int zero_tls;

__attribute__((constructor)) static void initialize(void)
{
    ++constructors;
}

__attribute__((destructor)) static void finalize(void)
{
    ++destructors;
}

int loader_iterate_open_reentrant_state(int *tag, int *constructor_count,
                                        int *destructor_count, int *initialized,
                                        int *zero)
{
    *tag = PLUGIN_TAG;
    *constructor_count = constructors;
    *destructor_count = destructors;
    *initialized = initialized_tls;
    *zero = zero_tls;
    return 0x51ab;
}

void loader_iterate_open_reentrant_set_tls(int initialized, int zero)
{
    initialized_tls = initialized;
    zero_tls = zero;
}
