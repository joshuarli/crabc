/*
 * The native-loader probe builds this source twice under distinct sonames
 * and symbol names.  The constructor/destructor state makes both explicit
 * close and close-on-drop observable through the process-global lookup scope.
 */

#ifndef LOADER_STATE_SYMBOL
#error "LOADER_STATE_SYMBOL must be supplied by the fixture build"
#endif

#ifndef LOADER_VALUE_SYMBOL
#error "LOADER_VALUE_SYMBOL must be supplied by the fixture build"
#endif

static volatile int state;

__attribute__((constructor)) static void loader_dlfcn_init(void)
{
    state = 1;
}

__attribute__((destructor)) static void loader_dlfcn_fini(void)
{
    state = 2;
}

int LOADER_STATE_SYMBOL(void)
{
    return state;
}

int LOADER_VALUE_SYMBOL(void)
{
    return 73;
}
