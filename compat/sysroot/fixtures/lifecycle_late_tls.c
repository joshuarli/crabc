/* Runtime-dlopen TLS fixture; it remains trace-neutral for lifecycle order. */
#include "lifecycle_trace.h"

static __thread int lifecycle_late_tls = 19;

__attribute__((constructor)) static void lifecycle_late_tls_constructor(void)
{
    lifecycle_require(lifecycle_late_tls == 19);
}

int lifecycle_late_tls_value(void)
{
    return lifecycle_late_tls;
}
