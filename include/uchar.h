#ifndef _UCHAR_H
#define _UCHAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#define __NEED_size_t
#define __NEED_mbstate_t
#include <bits/alltypes.h>

#if __cplusplus < 201103L
typedef unsigned short char16_t;
typedef unsigned int char32_t;
#endif

size_t c16rtomb(char *, char16_t, mbstate_t *);
size_t c32rtomb(char *, char32_t, mbstate_t *);
size_t mbrtoc16(char16_t *, const char *, size_t, mbstate_t *);
size_t mbrtoc32(char32_t *, const char *, size_t, mbstate_t *);

#ifdef __cplusplus
}
#endif

#endif
