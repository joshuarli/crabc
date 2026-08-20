#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <features.h>

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <sys/select.h>

int utimes(const char *, const struct timeval [2]);

/* GNU/BSD clock-administration interfaces. */
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct timezone;
int gettimeofday(struct timeval *restrict, void *restrict);
int settimeofday(const struct timeval *, const struct timezone *);
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
int adjtime(const struct timeval *, struct timeval *);
#endif

#endif

#endif
