#ifndef _TIME_H
#define _TIME_H

#include <features.h>
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)
/*
 * Keep the x86-64 time vocabulary sourced from the same generated alltypes
 * declarations as musl.  In particular, this makes the time_t/timespec and
 * clock-id requests explicit instead of relying on the umbrella sys/types.h
 * spelling.  The AArch64 branch below is retained unchanged for the active
 * libc target.
 */
#define __NEED_size_t
#define __NEED_time_t
#define __NEED_clock_t
#define __NEED_struct_timespec
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_clockid_t
#define __NEED_timer_t
#define __NEED_pid_t
#define __NEED_locale_t
#endif
#include <bits/alltypes.h>
#else
#include <sys/types.h>
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_locale_t
#include <bits/alltypes.h>
#endif
#endif

#ifndef NULL
#if defined(__x86_64__) && defined(__cplusplus)
#if __cplusplus >= 201103L
#define NULL nullptr
#else
#define NULL 0L
#endif
#else
#define NULL ((void*)0)
#endif
#endif

#define CLOCKS_PER_SEC 1000000L

#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7
#define CLOCK_REALTIME_ALARM     8
#define CLOCK_BOOTTIME_ALARM     9
#if defined(__x86_64__)
#define CLOCK_SGI_CYCLE          10
#endif
#define CLOCK_TAI               11

#define TIMER_ABSTIME 1
#define TIME_UTC 1


#ifndef __DEFINED_struct_timespec
#define __DEFINED_struct_timespec
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#ifndef _TIMEVAL_DEFINED
#define _TIMEVAL_DEFINED
struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

struct sigevent;
#endif
#endif

#if defined(__x86_64__) && (defined(_BSD_SOURCE) || defined(_GNU_SOURCE))
#define __tm_gmtoff tm_gmtoff
#define __tm_zone tm_zone
#elif defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
#define tm_gmtoff __tm_gmtoff
#define tm_zone __tm_zone
#endif

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long __tm_gmtoff;
    const char *__tm_zone;
};

clock_t clock(void);
time_t time(time_t *);
double difftime(time_t, time_t);
time_t mktime(struct tm *);
size_t strftime(char *, size_t, const char *, const struct tm *);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *strptime(const char *, const char *, struct tm *);
struct tm *getdate(const char *);
extern int getdate_err;
#endif
struct tm *gmtime(const time_t *);
struct tm *localtime(const time_t *);
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct tm *gmtime_r(const time_t *, struct tm *);
struct tm *localtime_r(const time_t *, struct tm *);
#endif
char *asctime(const struct tm *);
char *ctime(const time_t *);
int timespec_get(struct timespec *, int);
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE+0 < 202405L
char *asctime_r(const struct tm *, char *);
char *ctime_r(const time_t *, char *);
#endif
#endif
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
time_t timegm(struct tm *);
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int nanosleep(const struct timespec *, struct timespec *);
int clock_getres(int, struct timespec *);
int clock_gettime(int, struct timespec *);
int clock_settime(int, const struct timespec *);
int clock_nanosleep(int, int, const struct timespec *, struct timespec *);
int clock_getcpuclockid(pid_t, clockid_t *);
size_t strftime_l(char *, size_t, const char *, const struct tm *, locale_t);
int timer_create(clockid_t, struct sigevent *, timer_t *);
int timer_delete(timer_t);
int timer_getoverrun(timer_t);
int timer_gettime(timer_t, struct itimerspec *);
int timer_settime(timer_t, int, const struct itimerspec *, struct itimerspec *);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int stime(const time_t *);
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void tzset(void);
extern char *tzname[2];
#endif
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
extern int daylight;
extern long timezone;
#endif

#ifdef __cplusplus
}
#endif

#endif
