/* C++ companion for the native x86-64 <stdlib.h> integer-arithmetic probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

using abs_signature = int (*)(int);
using labs_signature = long (*)(long);
using llabs_signature = long long (*)(long long);
using div_signature = div_t (*)(int, int);
using ldiv_signature = ldiv_t (*)(long, long);
using lldiv_signature = lldiv_t (*)(long long, long long);

static_assert(__is_same(decltype(&abs), abs_signature), "abs declaration");
static_assert(__is_same(decltype(&labs), labs_signature), "labs declaration");
static_assert(__is_same(decltype(&llabs), llabs_signature), "llabs declaration");
static_assert(__is_same(decltype(&div), div_signature), "div declaration");
static_assert(__is_same(decltype(&ldiv), ldiv_signature), "ldiv declaration");
static_assert(__is_same(decltype(&lldiv), lldiv_signature), "lldiv declaration");

static_assert(sizeof(div_t) == 2 * sizeof(int), "div_t size");
static_assert(alignof(div_t) == alignof(int), "div_t alignment");
static_assert(offsetof(div_t, quot) == 0, "div_t quot offset");
static_assert(offsetof(div_t, rem) == sizeof(int), "div_t rem offset");

static_assert(sizeof(ldiv_t) == 2 * sizeof(long), "ldiv_t size");
static_assert(alignof(ldiv_t) == alignof(long), "ldiv_t alignment");
static_assert(offsetof(ldiv_t, quot) == 0, "ldiv_t quot offset");
static_assert(offsetof(ldiv_t, rem) == sizeof(long), "ldiv_t rem offset");

static_assert(sizeof(lldiv_t) == 2 * sizeof(long long), "lldiv_t size");
static_assert(alignof(lldiv_t) == alignof(long long), "lldiv_t alignment");
static_assert(offsetof(lldiv_t, quot) == 0, "lldiv_t quot offset");
static_assert(offsetof(lldiv_t, rem) == sizeof(long long), "lldiv_t rem offset");

int crabc_x86_64_integer_arithmetic_header_abi_probe_cpp()
{
    return 0;
}
