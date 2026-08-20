#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <sys/select.h>

int gettimeofday(struct timeval *restrict, void *restrict);
int settimeofday(const struct timeval *, const void *);
int utimes(const char *, const struct timeval [2]);

#endif
