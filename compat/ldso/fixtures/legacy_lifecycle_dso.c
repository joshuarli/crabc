#include <unistd.h>

static void marker(const char *text, unsigned long length)
{
    (void)write(1, text, length);
}

void legacy_init(void)
{
    marker("legacy-init\n", sizeof("legacy-init\n") - 1);
}

void legacy_fini(void)
{
    marker("legacy-fini\n", sizeof("legacy-fini\n") - 1);
}

__attribute__((constructor)) static void array_init(void)
{
    marker("legacy-array-init\n", sizeof("legacy-array-init\n") - 1);
}

__attribute__((destructor)) static void array_fini(void)
{
    marker("legacy-array-fini\n", sizeof("legacy-array-fini\n") - 1);
}

int legacy_value(void)
{
    return 37;
}
