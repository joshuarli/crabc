/* Normal C strong-override definitions for the three public weak aliases.
 *
 * This translation unit intentionally contains no caller.  The paired caller
 * is separately compiled so the compiler cannot fold a local constant return
 * into main: the linked public relocation is part of the receipt evidence.
 */
#include <resolv.h>

#ifndef CRABC_RESOLVER_ALIAS_OVERRIDE
# error "select one resolver alias override"
#endif

#if CRABC_RESOLVER_ALIAS_OVERRIDE == 1
int res_mkquery(int operation, const char *name, int class_, int type,
    const unsigned char *data, int data_length, const unsigned char *new_record,
    unsigned char *answer, int answer_length)
{
    (void)operation; (void)name; (void)class_; (void)type; (void)data;
    (void)data_length; (void)new_record; (void)answer; (void)answer_length;
    return 71;
}
#elif CRABC_RESOLVER_ALIAS_OVERRIDE == 2
int res_send(const unsigned char *query, int query_length, unsigned char *answer,
    int answer_length)
{
    (void)query; (void)query_length; (void)answer; (void)answer_length;
    return 72;
}
#elif CRABC_RESOLVER_ALIAS_OVERRIDE == 3
int res_search(const char *name, int class_, int type, unsigned char *answer,
    int answer_length)
{
    (void)name; (void)class_; (void)type; (void)answer; (void)answer_length;
    return 73;
}
#else
# error "unknown resolver alias override"
#endif
