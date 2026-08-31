/* C++17 companion for the Linux/x86-64 <sys/timeb.h> ftime declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/timeb.h>

static_assert(sizeof(time_t) == 8, "x86 time_t width");
static_assert(sizeof(struct timeb) == 16, "x86 timeb size");
static_assert(alignof(struct timeb) == 8, "x86 timeb alignment");
static_assert(offsetof(struct timeb, time) == 0, "timeb time offset");
static_assert(offsetof(struct timeb, millitm) == 8, "timeb millitm offset");
static_assert(offsetof(struct timeb, timezone) == 10, "timeb timezone offset");
static_assert(offsetof(struct timeb, dstflag) == 12, "timeb dstflag offset");

using ftime_signature = int (*)(struct timeb *);

static_assert(__is_same(decltype(&ftime), ftime_signature),
    "C++ ftime declaration");

static ftime_signature ftime_function = ftime;

int crabc_x86_64_ftime_header_abi_probe_cpp()
{
    return ftime_function != nullptr ? 0 : 1;
}
