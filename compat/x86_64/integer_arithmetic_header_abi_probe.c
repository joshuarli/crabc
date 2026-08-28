/* Source-only Linux/x86-64 <stdlib.h> integer-arithmetic ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

typedef int (*abs_signature)(int);
typedef long (*labs_signature)(long);
typedef long long (*llabs_signature)(long long);
typedef div_t (*div_signature)(int, int);
typedef ldiv_t (*ldiv_signature)(long, long);
typedef lldiv_t (*lldiv_signature)(long long, long long);

static abs_signature abs_function = abs;
static labs_signature labs_function = labs;
static llabs_signature llabs_function = llabs;
static div_signature div_function = div;
static ldiv_signature ldiv_function = ldiv;
static lldiv_signature lldiv_function = lldiv;

_Static_assert(sizeof(div_t) == 2 * sizeof(int), "div_t size");
_Static_assert(_Alignof(div_t) == _Alignof(int), "div_t alignment");
_Static_assert(offsetof(div_t, quot) == 0, "div_t quot offset");
_Static_assert(offsetof(div_t, rem) == sizeof(int), "div_t rem offset");

_Static_assert(sizeof(ldiv_t) == 2 * sizeof(long), "ldiv_t size");
_Static_assert(_Alignof(ldiv_t) == _Alignof(long), "ldiv_t alignment");
_Static_assert(offsetof(ldiv_t, quot) == 0, "ldiv_t quot offset");
_Static_assert(offsetof(ldiv_t, rem) == sizeof(long), "ldiv_t rem offset");

_Static_assert(sizeof(lldiv_t) == 2 * sizeof(long long), "lldiv_t size");
_Static_assert(_Alignof(lldiv_t) == _Alignof(long long), "lldiv_t alignment");
_Static_assert(offsetof(lldiv_t, quot) == 0, "lldiv_t quot offset");
_Static_assert(offsetof(lldiv_t, rem) == sizeof(long long), "lldiv_t rem offset");

int crabc_x86_64_integer_arithmetic_header_abi_probe(void)
{
    (void)abs_function;
    (void)labs_function;
    (void)llabs_function;
    (void)div_function;
    (void)ldiv_function;
    (void)lldiv_function;
    return 0;
}
