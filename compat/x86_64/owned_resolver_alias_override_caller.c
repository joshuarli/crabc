/* Separately compiled public callers for the normal C override controls. */
#include <resolv.h>

#ifndef CRABC_RESOLVER_ALIAS_OVERRIDE
# error "select one resolver alias override"
#endif

int main(void)
{
#if CRABC_RESOLVER_ALIAS_OVERRIDE == 1
    return res_mkquery(0, "fixture.test", 0, 0, 0, 0, 0, 0, 0) == 71 ? 0 : 1;
#elif CRABC_RESOLVER_ALIAS_OVERRIDE == 2
    return res_send(0, 0, 0, 0) == 72 ? 0 : 1;
#elif CRABC_RESOLVER_ALIAS_OVERRIDE == 3
    return res_search("fixture.test", 0, 0, 0, 0) == 73 ? 0 : 1;
#else
# error "unknown resolver alias override"
#endif
}
