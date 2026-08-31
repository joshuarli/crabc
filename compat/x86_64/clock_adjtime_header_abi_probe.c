/* Pinned-musl/project Linux/x86-64 clock_adjtime declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/timex.h>

typedef int (*clock_adjtime_signature)(clockid_t, struct timex *);

_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timex) == 208 && _Alignof(struct timex) == 8,
    "x86 timex layout");
_Static_assert(offsetof(struct timex, time) == 72 &&
    offsetof(struct timex, tai) == 160 &&
    offsetof(struct timex, __padding) == 164, "x86 timex field offsets");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_adjtime),
    clock_adjtime_signature), "clock_adjtime declaration");

static clock_adjtime_signature clock_adjtime_function __attribute__((used)) =
    clock_adjtime;

int crabc_x86_64_clock_adjtime_header_abi_probe(void)
{
    return clock_adjtime_function != (clock_adjtime_signature)0 ? 0 : 1;
}
