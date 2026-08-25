/* Middle dependency fixture; it establishes a non-accidental DSO graph. */
#include "lifecycle_trace.h"

int lifecycle_leaf_value(void);

__attribute__((constructor(200))) static void lifecycle_mid_constructor(void)
{
    lifecycle_require(lifecycle_leaf_value() == 11);
    lifecycle_trace('M');
}

__attribute__((destructor(200))) static void lifecycle_mid_destructor(void)
{
    lifecycle_trace('m');
}

int lifecycle_mid_value(void)
{
    return lifecycle_leaf_value();
}
