/* Pinned-musl/project Linux/x86-64 res_init declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

typedef int (*res_init_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&res_init),
                                             res_init_signature),
               "res_init declaration");

static res_init_signature res_init_function __attribute__((used)) = res_init;

int crabc_x86_64_res_init_header_abi_probe(void)
{
    return res_init_function != (res_init_signature)0 ? 0 : 1;
}
