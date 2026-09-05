/* Installed-header C++17 witness for the selected native monetary ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <monetary.h>

using strfmon_signature = ssize_t (*)(char *, size_t, const char *, ...);
using strfmon_l_signature = ssize_t (*)(char *, size_t, locale_t,
    const char *, ...);

static_assert(sizeof(ssize_t) == sizeof(long), "LP64 ssize_t");
static_assert(alignof(ssize_t) == alignof(long), "LP64 ssize_t alignment");
static_assert(sizeof(locale_t) == sizeof(void *), "opaque locale token width");
static_assert(__is_same(decltype(&strfmon), strfmon_signature),
    "strfmon declaration");
static_assert(__is_same(decltype(&strfmon_l), strfmon_l_signature),
    "strfmon_l declaration");

extern "C" strfmon_signature crabc_x86_64_strfmon_header_cxx()
{
    return strfmon;
}

extern "C" strfmon_l_signature crabc_x86_64_strfmon_l_header_cxx()
{
    return strfmon_l;
}
