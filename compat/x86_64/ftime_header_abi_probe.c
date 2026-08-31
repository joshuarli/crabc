/* Pinned-musl/project Linux/x86-64 <sys/timeb.h> ftime declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/timeb.h>

_Static_assert(sizeof(time_t) == 8, "x86 time_t width");
_Static_assert(sizeof(struct timeb) == 16, "x86 timeb size");
_Static_assert(_Alignof(struct timeb) == 8, "x86 timeb alignment");
_Static_assert(offsetof(struct timeb, time) == 0, "timeb time offset");
_Static_assert(offsetof(struct timeb, millitm) == 8, "timeb millitm offset");
_Static_assert(offsetof(struct timeb, timezone) == 10, "timeb timezone offset");
_Static_assert(offsetof(struct timeb, dstflag) == 12, "timeb dstflag offset");
_Static_assert(sizeof(((struct timeb *)0)->millitm) == 2,
    "timeb millitm width");
_Static_assert(sizeof(((struct timeb *)0)->timezone) == 2,
    "timeb timezone width");
_Static_assert(sizeof(((struct timeb *)0)->dstflag) == 2,
    "timeb dstflag width");

typedef int (*ftime_signature)(struct timeb *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&ftime),
    ftime_signature), "ftime declaration");

static ftime_signature ftime_function = ftime;

int crabc_x86_64_ftime_header_abi_probe(void)
{
    return ftime_function != (ftime_signature)0 ? 0 : 1;
}
