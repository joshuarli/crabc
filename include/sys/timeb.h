#ifndef _SYS_TIMEB_H
#define _SYS_TIMEB_H

#include <features.h>

#define __NEED_time_t

#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timeb {
    time_t time;
    unsigned short millitm;
    short timezone;
    short dstflag;
};

int ftime(struct timeb *);

#ifdef __cplusplus
}
#endif

#endif
