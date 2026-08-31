/* Pinned-musl/project Linux/x86-64 <ulimit.h> declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <ulimit.h>

#if defined(CRABC_EXPECT_ULIMIT)
typedef long (*ulimit_signature)(int, ...);

_Static_assert(sizeof(long) == 8, "x86 LP64 long width");
_Static_assert(UL_GETFSIZE == 1 && UL_SETFSIZE == 2,
    "musl historical ulimit commands");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ulimit),
    ulimit_signature), "ulimit declaration");

static ulimit_signature ulimit_function __attribute__((used)) = ulimit;
#endif

int crabc_x86_64_ulimit_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_ULIMIT)
    return ulimit_function == (ulimit_signature)0;
#else
    return 0;
#endif
}
