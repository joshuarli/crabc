#ifndef _UTIME_H
#define _UTIME_H

#include <features.h>

#define __NEED_time_t

#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct utimbuf {
    time_t actime;
    time_t modtime;
};

int utime(const char *, const struct utimbuf *);

#if defined(_REDIR_TIME64) && _REDIR_TIME64
__REDIR(utime, __utime64);
#endif

#ifdef __cplusplus
}
#endif

#endif
