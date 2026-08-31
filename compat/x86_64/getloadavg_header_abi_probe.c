/* Pinned-musl/project Linux/x86-64 getloadavg declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_GETLOADAVG_EXPECT_HIDDEN)
int crabc_x86_64_getloadavg_header_abi_hidden_probe(void)
{
    return getloadavg((double *)0, 0);
}
#else
typedef int (*getloadavg_signature)(double *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getloadavg),
    getloadavg_signature), "getloadavg declaration");

static getloadavg_signature getloadavg_function __attribute__((used)) = getloadavg;

int crabc_x86_64_getloadavg_header_abi_probe(void)
{
    return getloadavg_function != (getloadavg_signature)0 ? 0 : 1;
}
#endif
