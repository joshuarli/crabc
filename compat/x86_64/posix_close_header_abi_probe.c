/* Pinned-musl/project Linux/x86-64 posix_close declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*posix_close_signature)(int, int);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 posix_close int ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_close),
                                             posix_close_signature),
               "posix_close declaration");

static posix_close_signature posix_close_function __attribute__((used)) =
    posix_close;

int crabc_x86_64_posix_close_header_abi_probe(void)
{
    return posix_close_function != (posix_close_signature)0 ? 0 : 1;
}
