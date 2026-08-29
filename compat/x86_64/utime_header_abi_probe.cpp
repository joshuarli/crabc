/* C++17 companion for the Linux/x86-64 <utime.h> ABI/linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <utime.h>

static_assert(sizeof(time_t) == 8 && sizeof(struct utimbuf) == 16,
    "x86 C++ utime record width");
static_assert(alignof(struct utimbuf) == 8 &&
    offsetof(struct utimbuf, actime) == 0 && offsetof(struct utimbuf, modtime) == 8,
    "x86 C++ utime record layout");

using utime_signature = int (*)(const char *, const struct utimbuf *);
static_assert(__is_same(decltype(&utime), utime_signature),
    "utime C++ declaration");

__attribute__((used)) static utime_signature crabc_x86_64_utime_c_linkage = utime;
