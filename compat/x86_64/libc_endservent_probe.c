/* Native Linux/x86-64 static endservent C ABI evidence.
 *
 * The project-header body first executes through pinned musl 1.2.6 and then
 * through one archive-free freestanding crabc object. Musl's serv.c body
 * makes endservent a no-op. This fixture proves direct and function-pointer
 * calls only; it selects no service enumeration, database, resolver,
 * filesystem, state, or runtime policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef void (*endservent_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endservent),
                                             endservent_signature),
               "endservent declaration");

int crabc_x86_64_endservent_probe(void)
{
    const endservent_signature function = endservent;

    endservent();
    function();
    return 0;
}

#ifndef CRABC_ENDSERVENT_FREESTANDING
int main(void)
{
    return crabc_x86_64_endservent_probe();
}
#endif
