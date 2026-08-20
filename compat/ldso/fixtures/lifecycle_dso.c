#include <unistd.h>

static int lifecycle_state;

__attribute__((constructor))
static void lifecycle_constructor(void)
{
    lifecycle_state = 73;
    write(1, "ctor\n", 5);
}

__attribute__((destructor))
static void lifecycle_destructor(void)
{
    write(1, "dtor\n", 5);
}

int lifecycle_value(void)
{
    return lifecycle_state;
}
