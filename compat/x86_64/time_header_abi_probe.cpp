/* C++ source-only companion for the native x86-64 <time.h> ABI probe. */
#define _GNU_SOURCE 1

#include <stddef.h>
#include <time.h>

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native x86-64 LP64"
#endif

static_assert(sizeof(time_t) == 8, "x86 time_t");
static_assert(sizeof(clock_t) == 8, "x86 clock_t");
static_assert(sizeof(clockid_t) == 4, "x86 clockid_t");
static_assert(sizeof(timer_t) == 8, "x86 timer_t");
static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
static_assert(offsetof(struct timespec, tv_sec) == 0, "timespec tv_sec");
static_assert(offsetof(struct timespec, tv_nsec) == 8, "timespec tv_nsec");
static_assert(sizeof(struct itimerspec) == 32, "x86 itimerspec size");
static_assert(sizeof(struct tm) == 56, "x86 tm size");
static_assert(offsetof(struct tm, tm_gmtoff) == 40, "tm_gmtoff");
static_assert(offsetof(struct tm, tm_zone) == 48, "tm_zone");

static_assert(CLOCK_SGI_CYCLE == 10, "CLOCK_SGI_CYCLE");
static_assert(CLOCK_TAI == 11, "CLOCK_TAI");
static_assert(TIMER_ABSTIME == 1, "TIMER_ABSTIME");
static_assert(TIME_UTC == 1, "TIME_UTC");

static clock_t (*clock_signature)(void) = clock;
static time_t (*timegm_signature)(struct tm *) = timegm;
static int (*clock_gettime_signature)(clockid_t, struct timespec *) = clock_gettime;
static int (*clock_nanosleep_signature)(clockid_t, int, const struct timespec *,
                                        struct timespec *) = clock_nanosleep;
static int (*timer_create_signature)(clockid_t, struct sigevent *, timer_t *) = timer_create;

int main()
{
    struct tm calendar = {};
    calendar.tm_gmtoff = 0;
    calendar.tm_zone = NULL;
    (void)clock_signature;
    (void)timegm_signature;
    (void)clock_gettime_signature;
    (void)clock_nanosleep_signature;
    (void)timer_create_signature;
    return calendar.tm_zone != NULL;
}
