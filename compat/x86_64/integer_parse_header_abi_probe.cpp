/* C++ companion for the native x86-64 integer-parsing declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <inttypes.h>
#include <stdlib.h>

using atoi_signature = int (*)(const char *);
using atol_signature = long (*)(const char *);
using atoll_signature = long long (*)(const char *);
using strtol_signature = long (*)(const char *, char **, int);
using strtoul_signature = unsigned long (*)(const char *, char **, int);
using strtoll_signature = long long (*)(const char *, char **, int);
using strtoull_signature = unsigned long long (*)(const char *, char **, int);
using strtoimax_signature = intmax_t (*)(const char *, char **, int);
using strtoumax_signature = uintmax_t (*)(const char *, char **, int);

static_assert(__is_same(decltype(&atoi), atoi_signature), "atoi declaration");
static_assert(__is_same(decltype(&atol), atol_signature), "atol declaration");
static_assert(__is_same(decltype(&atoll), atoll_signature), "atoll declaration");
static_assert(__is_same(decltype(&strtol), strtol_signature), "strtol declaration");
static_assert(__is_same(decltype(&strtoul), strtoul_signature), "strtoul declaration");
static_assert(__is_same(decltype(&strtoll), strtoll_signature), "strtoll declaration");
static_assert(__is_same(decltype(&strtoull), strtoull_signature), "strtoull declaration");
static_assert(__is_same(decltype(&strtoimax), strtoimax_signature), "strtoimax declaration");
static_assert(__is_same(decltype(&strtoumax), strtoumax_signature), "strtoumax declaration");
static_assert(sizeof(intmax_t) == sizeof(long), "x86 LP64 intmax_t width");
static_assert(sizeof(uintmax_t) == sizeof(unsigned long), "x86 LP64 uintmax_t width");

int crabc_x86_64_integer_parse_header_abi_probe_cpp()
{
    return 0;
}
