/* Pinned-musl/project Linux/x86-64 clock_adjtime C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/timex.h>

using clock_adjtime_signature = int (*)(clockid_t, struct timex *);

static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
static_assert(sizeof(struct timex) == 208 && alignof(struct timex) == 8,
    "x86 timex layout");
static_assert(__builtin_offsetof(struct timex, time) == 72 &&
    __builtin_offsetof(struct timex, tai) == 160 &&
    __builtin_offsetof(struct timex, __padding) == 164,
    "x86 timex field offsets");
static_assert(__is_same(decltype(&clock_adjtime), clock_adjtime_signature),
    "clock_adjtime declaration");

static clock_adjtime_signature clock_adjtime_function __attribute__((used)) =
    clock_adjtime;

int crabc_x86_64_clock_adjtime_header_abi_probe_cpp()
{
    return clock_adjtime_function != nullptr ? 0 : 1;
}
