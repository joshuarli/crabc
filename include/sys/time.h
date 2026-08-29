#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <features.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

int gettimeofday(struct timeval *__restrict, void *__restrict);

#define ITIMER_REAL 0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

int getitimer(int, struct itimerval *);
int setitimer(int, const struct itimerval *__restrict, struct itimerval *__restrict);
int utimes(const char *, const struct timeval [2]);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

int futimes(int, const struct timeval [2]);
int futimesat(int, const char *, const struct timeval [2]);
int lutimes(const char *, const struct timeval [2]);
int settimeofday(const struct timeval *, const struct timezone *);
int adjtime(const struct timeval *, struct timeval *);

#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)
#define timerclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timercmp(s, t, op) ((s)->tv_sec == (t)->tv_sec ? \
    (s)->tv_usec op (t)->tv_usec : (s)->tv_sec op (t)->tv_sec)
#define timeradd(s, t, v) do { \
    (v)->tv_sec = (s)->tv_sec + (t)->tv_sec; \
    (v)->tv_usec = (s)->tv_usec + (t)->tv_usec; \
    if ((v)->tv_usec >= 1000000) { \
        (v)->tv_sec++; \
        (v)->tv_usec -= 1000000; \
    } \
} while (0)
#define timersub(s, t, v) do { \
    (v)->tv_sec = (s)->tv_sec - (t)->tv_sec; \
    (v)->tv_usec = (s)->tv_usec - (t)->tv_usec; \
    if ((v)->tv_usec < 0) { \
        (v)->tv_sec--; \
        (v)->tv_usec += 1000000; \
    } \
} while (0)
#endif

#if defined(_GNU_SOURCE)
#define TIMEVAL_TO_TIMESPEC(tv, ts) do { \
    (ts)->tv_sec = (tv)->tv_sec; \
    (ts)->tv_nsec = (tv)->tv_usec * 1000; \
} while (0)
#define TIMESPEC_TO_TIMEVAL(tv, ts) do { \
    (tv)->tv_sec = (ts)->tv_sec; \
    (tv)->tv_usec = (ts)->tv_nsec / 1000; \
} while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif
