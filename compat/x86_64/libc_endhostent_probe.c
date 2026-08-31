/* Native Linux/x86-64 static endhostent/endnetent C ABI evidence.
 *
 * The project-header body first executes through pinned musl 1.2.6 and then
 * through one true freestanding crabc archive. Musl's ent.c body makes
 * endhostent a no-op and emits endnetent as its weak same-address alias; this
 * fixture proves direct and function-pointer calls plus that exact alias
 * identity. It selects no host/network enumeration, resolver, database,
 * filesystem, state, or runtime policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef void (*endhostent_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endhostent),
                                             endhostent_signature),
               "endhostent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endnetent),
                                             endhostent_signature),
               "endnetent declaration");

int crabc_x86_64_endhostent_probe(void)
{
    const endhostent_signature host_function = endhostent;
    const endhostent_signature net_function = endnetent;

    if (host_function != net_function)
        return 1;
    endhostent();
    endnetent();
    host_function();
    net_function();
    return 0;
}

#ifndef CRABC_ENDHOSTENT_FREESTANDING
int main(void)
{
    return crabc_x86_64_endhostent_probe();
}
#endif
