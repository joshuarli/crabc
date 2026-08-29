/* C++17 companion for the Linux/x86-64 timeval transitive-header ABI probe. */

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

static_assert(sizeof(struct timeval) == 16 && alignof(struct timeval) == 8,
              "x86 timeval ABI");
static_assert(__builtin_offsetof(struct timeval, tv_sec) == 0 &&
                  __builtin_offsetof(struct timeval, tv_usec) == 8,
              "x86 timeval offsets");

#if defined(CRABC_TIMEVAL_TARGET_UTMPX) || defined(CRABC_TIMEVAL_TARGET_UTMP)
static_assert(sizeof(struct utmpx) == 400 && alignof(struct utmpx) == 8,
              "x86 utmpx ABI");
static_assert(__builtin_offsetof(struct utmpx, ut_tv) == 344 &&
                  __builtin_offsetof(struct utmpx, ut_addr_v6) == 360 &&
                  __builtin_offsetof(struct utmpx, __unused) == 376,
              "x86 utmpx timeval offsets");
#endif

#if defined(CRABC_TIMEVAL_TARGET_UTMP) || defined(CRABC_TIMEVAL_TARGET_LASTLOG)
static_assert(sizeof(struct lastlog) == 296 && alignof(struct lastlog) == 8,
              "x86 lastlog ABI");
static_assert(__builtin_offsetof(struct lastlog, ll_time) == 0 &&
                  __builtin_offsetof(struct lastlog, ll_line) == 8 &&
                  __builtin_offsetof(struct lastlog, ll_host) == 40,
              "x86 lastlog offsets");
#endif

#if defined(CRABC_TIMEVAL_TARGET_SYS_TIMEX)
static_assert(sizeof(struct ntptimeval) == 32 && alignof(struct ntptimeval) == 8,
              "x86 ntptimeval ABI");
static_assert(__builtin_offsetof(struct ntptimeval, time) == 0 &&
                  __builtin_offsetof(struct ntptimeval, maxerror) == 16 &&
                  __builtin_offsetof(struct ntptimeval, esterror) == 24,
              "x86 ntptimeval offsets");
static_assert(sizeof(struct timex) == 208 && alignof(struct timex) == 8,
              "x86 timex ABI");
static_assert(__builtin_offsetof(struct timex, time) == 72 &&
                  __builtin_offsetof(struct timex, tai) == 160 &&
                  __builtin_offsetof(struct timex, __padding) == 164,
              "x86 timex timeval offsets");
#endif
