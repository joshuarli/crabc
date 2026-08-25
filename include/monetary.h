#ifndef _MONETARY_H
#define _MONETARY_H

#include <features.h>
#define __NEED_size_t
#define __NEED_ssize_t
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_locale_t
#endif
#include <bits/alltypes.h>

ssize_t strfmon(char *__restrict, size_t, const char *__restrict, ...);
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
ssize_t strfmon_l(char *__restrict, size_t, locale_t, const char *__restrict, ...);
#endif

#endif
