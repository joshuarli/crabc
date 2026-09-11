/* Native x86-64 C declaration witness for stdlib rand/srand. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this witness requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

typedef int (*rand_signature)(void);
typedef void (*srand_signature)(unsigned);

_Static_assert(sizeof(unsigned) == 4, "C unsigned is 32 bits");
_Static_assert(sizeof(int) == 4, "C int is 32 bits");
_Static_assert(RAND_MAX == 0x7fffffff, "rand result bound");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rand), rand_signature),
    "rand C declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srand), srand_signature),
    "srand C declaration");

int crabc_owned_rand_header_abi_probe_c(void)
{
    rand_signature next = rand;
    srand_signature seed = srand;
    seed(1U);
    return next() < 0;
}
