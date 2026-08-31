/* Static x86-64 gethostid C ABI and behavior fixture.
 *
 * Musl's Linux implementation returns the fixed zero `long` value. This
 * isolated fixture deliberately does not consult hostname/domain-name state
 * or any host-specific file.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

_Static_assert(sizeof(long) == 8, "Linux/x86-64 LP64 long");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gethostid),
    long (*)(void)), "gethostid declaration");

typedef long (*gethostid_signature)(void);

int crabc_x86_64_gethostid_probe(void)
{
    const gethostid_signature function = gethostid;

    if (gethostid() != 0L)
        return 1;
    if (function() != 0L)
        return 2;
    return gethostid() == 0L ? 0 : 3;
}

#ifndef CRABC_GETHOSTID_FREESTANDING
int main(void)
{
    return crabc_x86_64_gethostid_probe();
}
#endif
