/* Native Linux/x86-64 static res_init C ABI evidence.
 *
 * Musl's complete res_init.c body returns zero without consulting resolver
 * state or configuration. This fixture therefore observes only that private
 * successful no-op, not _res, /etc/resolv.conf, DNS, sockets, or netdb.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

#ifndef CRABC_RES_INIT_FREESTANDING
#include <errno.h>
#endif

typedef int (*res_init_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&res_init),
                                             res_init_signature),
               "res_init declaration");

int crabc_x86_64_res_init_probe(void)
{
    const res_init_signature function = res_init;

    if (res_init() != 0)
        return 1;
    if (function() != 0)
        return 2;

#ifndef CRABC_RES_INIT_FREESTANDING
    errno = E2BIG;
    if (res_init() != 0)
        return 3;
    if (errno != E2BIG)
        return 4;
#endif

    return 0;
}

#ifndef CRABC_RES_INIT_FREESTANDING
int main(void)
{
    return crabc_x86_64_res_init_probe();
}
#endif
