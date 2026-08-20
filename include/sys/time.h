#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <sys/select.h>

struct timezone;
int gettimeofday(struct timeval *restrict, void *restrict);
int settimeofday(const struct timeval *, const struct timezone *);
int utimes(const char *, const struct timeval [2]);

/* GNU/BSD clock-administration interfaces. */
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
int adjtime(const struct timeval *, struct timeval *);

#endif
