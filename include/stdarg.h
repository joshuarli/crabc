#if defined(__x86_64__)
#ifndef _STDARG_H
#define _STDARG_H

#ifdef __cplusplus
extern "C" {
#endif

#define __NEED_va_list

#include <bits/alltypes.h>

#define va_start(v,l)   __builtin_va_start(v,l)
#define va_end(v)       __builtin_va_end(v)
#define va_arg(v,l)     __builtin_va_arg(v,l)
#define va_copy(d,s)    __builtin_va_copy(d,s)

#ifdef __cplusplus
}
#endif

#endif
#else
#ifndef _CRABC_STDARG_H
#define _CRABC_STDARG_H

typedef __builtin_va_list va_list;
typedef __builtin_va_list __isoc_va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dst, src) __builtin_va_copy(dst, src)

#endif
#endif
