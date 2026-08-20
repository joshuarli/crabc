#ifndef _CRABC_UTIME_H
#define _CRABC_UTIME_H

#include <sys/types.h>
#include <features.h>

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
