/* Linked dependency fixture; its C source is an application object. */
#include <stdlib.h>

#include "lifecycle_trace.h"

static __thread int lifecycle_leaf_tls = 11;

__attribute__((constructor(200))) static void lifecycle_leaf_constructor(void)
{
    void *allocation;

    lifecycle_require(lifecycle_leaf_tls == 11);
    allocation = malloc(32);
    lifecycle_require(allocation != NULL);
    free(allocation);
    lifecycle_trace('L');
}

__attribute__((destructor(200))) static void lifecycle_leaf_destructor(void)
{
    lifecycle_trace('l');
}

int lifecycle_leaf_value(void)
{
    return lifecycle_leaf_tls;
}
