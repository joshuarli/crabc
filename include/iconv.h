#ifndef _ICONV_H
#define _ICONV_H

#include <features.h>
#define __NEED_size_t
#include <bits/alltypes.h>

typedef void *iconv_t;

iconv_t iconv_open(const char *, const char *);
size_t iconv(iconv_t, char **restrict, size_t *restrict,
             char **restrict, size_t *restrict);
int iconv_close(iconv_t);

#endif
