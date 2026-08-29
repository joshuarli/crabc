/* Source-only Linux/x86-64 <utime.h> ABI and linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <utime.h>

_Static_assert(sizeof(time_t) == 8 && sizeof(struct utimbuf) == 16,
    "x86 utime record width");
_Static_assert(_Alignof(struct utimbuf) == 8 &&
    offsetof(struct utimbuf, actime) == 0 && offsetof(struct utimbuf, modtime) == 8,
    "x86 utime record layout");

typedef int (*utime_signature)(const char *, const struct utimbuf *);
_Static_assert(__builtin_types_compatible_p(__typeof__(&utime), utime_signature),
    "utime declaration");

int crabc_x86_64_utime_header_abi_probe(void)
{
    struct utimbuf value = { 0, 0 };
    return (int)(value.actime + value.modtime);
}
