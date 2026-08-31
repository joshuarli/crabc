/* Pinned-musl/project Linux/x86-64 isatty declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*isatty_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&isatty),
    isatty_signature), "isatty declaration");

static isatty_signature isatty_function = isatty;

int crabc_x86_64_isatty_header_abi_probe(void)
{
    return isatty_function != (isatty_signature)0 ? 0 : 1;
}
