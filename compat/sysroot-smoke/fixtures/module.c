/* Loadable module used by the extracted-sysroot dlopen smoke. */

static int constructor_seen;

__attribute__((constructor)) static void module_constructor(void)
{
    constructor_seen = 1;
}

int crabc_sysroot_smoke_value(void)
{
    return constructor_seen ? 42 : 0;
}
