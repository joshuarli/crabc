/* Selected Linux/x86-64 <sys/timerfd.h> declaration and record contract. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/timerfd.h>

typedef int (*crabc_timerfd_create_signature)(int, int);
typedef int (*crabc_timerfd_settime_signature)(
    int, int, const struct itimerspec *, struct itimerspec *);
typedef int (*crabc_timerfd_gettime_signature)(int, struct itimerspec *);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define CRABC_TIMERFD_ITIMERSPEC_VISIBLE 1
#endif

_Static_assert(TFD_NONBLOCK == O_NONBLOCK && TFD_NONBLOCK == 0x800,
               "x86 timerfd nonblocking flag");
_Static_assert(TFD_CLOEXEC == O_CLOEXEC && TFD_CLOEXEC == 0x80000,
               "x86 timerfd close-on-exec flag");
_Static_assert(TFD_TIMER_ABSTIME == 1 && TFD_TIMER_CANCEL_ON_SET == 2,
               "x86 timerfd settime flags");
#ifdef CRABC_TIMERFD_ITIMERSPEC_VISIBLE
_Static_assert(sizeof(struct timespec) == 16 &&
                   _Alignof(struct timespec) == 8,
               "x86 timespec size/alignment");
_Static_assert(sizeof(struct itimerspec) == 32 &&
                   _Alignof(struct itimerspec) == 8 &&
                   offsetof(struct itimerspec, it_interval) == 0 &&
                   offsetof(struct itimerspec, it_value) == 16,
               "x86 itimerspec layout");
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_create),
                                             crabc_timerfd_create_signature),
               "timerfd_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_settime),
                                             crabc_timerfd_settime_signature),
               "timerfd_settime declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_gettime),
                                             crabc_timerfd_gettime_signature),
               "timerfd_gettime declaration");

int crabc_x86_64_timerfd_header_abi_probe(void)
{
#ifdef CRABC_TIMERFD_ITIMERSPEC_VISIBLE
    return (int)sizeof(struct itimerspec);
#else
    /* Strict C retains the timerfd declarations but `time.h` intentionally
     * leaves this POSIX timer record incomplete. */
    return 0;
#endif
}
