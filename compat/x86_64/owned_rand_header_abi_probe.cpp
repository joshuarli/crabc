/* Native x86-64 C++ declaration witness for stdlib rand/srand. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this witness requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

using rand_signature = int (*)();
using srand_signature = void (*)(unsigned);

static_assert(sizeof(unsigned) == 4, "C++ unsigned is 32 bits");
static_assert(sizeof(int) == 4, "C++ int is 32 bits");
static_assert(RAND_MAX == 0x7fffffff, "rand result bound");
static_assert(__is_same(decltype(&rand), rand_signature), "rand C++ declaration");
static_assert(__is_same(decltype(&srand), srand_signature), "srand C++ declaration");

int crabc_owned_rand_header_abi_probe_cpp()
{
    rand_signature next = rand;
    srand_signature seed = srand;
    seed(1U);
    return next() < 0;
}
