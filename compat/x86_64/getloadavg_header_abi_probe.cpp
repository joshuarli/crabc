/* Pinned-musl/project Linux/x86-64 getloadavg C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_GETLOADAVG_EXPECT_HIDDEN)
int crabc_x86_64_getloadavg_header_abi_hidden_probe_cpp()
{
    return getloadavg(nullptr, 0);
}
#else
using getloadavg_signature = int (*)(double *, int);

static_assert(__is_same(decltype(&getloadavg), getloadavg_signature),
    "C++ getloadavg declaration");

static getloadavg_signature getloadavg_function __attribute__((used)) = getloadavg;

int crabc_x86_64_getloadavg_header_abi_probe_cpp()
{
    return getloadavg_function != nullptr ? 0 : 1;
}
#endif
