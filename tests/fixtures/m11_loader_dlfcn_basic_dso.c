/*
 * The M11 native-loader probe builds this source twice under distinct sonames
 * and symbol names.  The constructor/destructor state makes both explicit
 * close and close-on-drop observable through the process-global lookup scope.
 */

#ifndef M11_STATE_SYMBOL
#error "M11_STATE_SYMBOL must be supplied by the fixture build"
#endif

#ifndef M11_VALUE_SYMBOL
#error "M11_VALUE_SYMBOL must be supplied by the fixture build"
#endif

static volatile int state;

__attribute__((constructor)) static void m11_loader_init(void)
{
    state = 1;
}

__attribute__((destructor)) static void m11_loader_fini(void)
{
    state = 2;
}

int M11_STATE_SYMBOL(void)
{
    return state;
}

int M11_VALUE_SYMBOL(void)
{
    return 73;
}
