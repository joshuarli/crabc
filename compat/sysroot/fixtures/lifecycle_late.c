/* Runtime-dlopen fixture; it proves one-shot dlclose cleanup. */
#include "lifecycle_trace.h"

static int lifecycle_late_value_state = 17;

__attribute__((constructor)) static void lifecycle_late_constructor(void)
{
    lifecycle_require(lifecycle_late_value_state == 17);
    lifecycle_trace('D');
}

__attribute__((destructor)) static void lifecycle_late_destructor(void)
{
    lifecycle_trace('d');
}

int lifecycle_late_value(void)
{
    return lifecycle_late_value_state;
}
