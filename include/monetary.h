#ifndef _MONETARY_H
#define _MONETARY_H

#include <locale.h>
#include <sys/types.h>

ssize_t strfmon(char *restrict, size_t, const char *restrict, ...);
ssize_t strfmon_l(char *restrict, size_t, locale_t, const char *restrict, ...);

#endif
