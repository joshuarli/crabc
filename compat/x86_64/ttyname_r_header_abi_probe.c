/* Pinned-musl/project Linux/x86-64 ttyname_r declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*ttyname_r_signature)(int, char *, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&ttyname_r),
    ttyname_r_signature), "ttyname_r declaration");

static ttyname_r_signature ttyname_r_function = ttyname_r;

int crabc_x86_64_ttyname_r_header_abi_probe(void)
{
    return ttyname_r_function != (ttyname_r_signature)0 ? 0 : 1;
}
