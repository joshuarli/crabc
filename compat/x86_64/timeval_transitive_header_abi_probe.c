/* Selected Linux/x86-64 timeval transitive-header ABI facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>

#if (defined(CRABC_TIMEVAL_TARGET_SYS_TIME) + defined(CRABC_TIMEVAL_TARGET_UTMPX) + \
     defined(CRABC_TIMEVAL_TARGET_UTMP) + defined(CRABC_TIMEVAL_TARGET_LASTLOG) + \
     defined(CRABC_TIMEVAL_TARGET_SYS_TIMEX)) != 1
#error "exactly one CRABC_TIMEVAL_TARGET_* selector is required"
#endif

#if defined(CRABC_TIMEVAL_TARGET_SYS_TIME)
#include <sys/time.h>
#elif defined(CRABC_TIMEVAL_TARGET_UTMPX)
#include <utmpx.h>
#elif defined(CRABC_TIMEVAL_TARGET_UTMP)
#include <utmp.h>
#elif defined(CRABC_TIMEVAL_TARGET_LASTLOG)
#include <lastlog.h>
#elif defined(CRABC_TIMEVAL_TARGET_SYS_TIMEX)
#include <sys/timex.h>
#else
#error "one CRABC_TIMEVAL_TARGET_* selector is required"
#endif

_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
               "x86 timeval ABI");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
                   offsetof(struct timeval, tv_usec) == 8,
               "x86 timeval offsets");

#if defined(CRABC_TIMEVAL_TARGET_UTMPX) || defined(CRABC_TIMEVAL_TARGET_UTMP)
_Static_assert(sizeof(struct utmpx) == 400 && _Alignof(struct utmpx) == 8,
               "x86 utmpx ABI");
_Static_assert(offsetof(struct utmpx, ut_tv) == 344 &&
                   offsetof(struct utmpx, ut_addr_v6) == 360 &&
                   offsetof(struct utmpx, __unused) == 376,
               "x86 utmpx timeval offsets");
#endif

#if defined(CRABC_TIMEVAL_TARGET_UTMP) || defined(CRABC_TIMEVAL_TARGET_LASTLOG)
_Static_assert(sizeof(struct lastlog) == 296 && _Alignof(struct lastlog) == 8,
               "x86 lastlog ABI");
_Static_assert(offsetof(struct lastlog, ll_time) == 0 &&
                   offsetof(struct lastlog, ll_line) == 8 &&
                   offsetof(struct lastlog, ll_host) == 40,
               "x86 lastlog offsets");
#endif

#if defined(CRABC_TIMEVAL_TARGET_SYS_TIMEX)
_Static_assert(sizeof(struct ntptimeval) == 32 && _Alignof(struct ntptimeval) == 8,
               "x86 ntptimeval ABI");
_Static_assert(offsetof(struct ntptimeval, time) == 0 &&
                   offsetof(struct ntptimeval, maxerror) == 16 &&
                   offsetof(struct ntptimeval, esterror) == 24,
               "x86 ntptimeval offsets");
_Static_assert(sizeof(struct timex) == 208 && _Alignof(struct timex) == 8,
               "x86 timex ABI");
_Static_assert(offsetof(struct timex, time) == 72 && offsetof(struct timex, tai) == 160 &&
                   offsetof(struct timex, __padding) == 164,
               "x86 timex timeval offsets");
#endif
