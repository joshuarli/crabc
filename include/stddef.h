#if defined(__x86_64__)

#ifndef _STDDEF_H
#define _STDDEF_H

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_ptrdiff_t
#define __NEED_size_t
#define __NEED_wchar_t
#if __STDC_VERSION__ >= 201112L || __cplusplus >= 201103L
#define __NEED_max_align_t
#endif

#include <bits/alltypes.h>

#if __GNUC__ > 3
#define offsetof(type, member) __builtin_offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)( (char *)&(((type *)0)->member) - (char *)0 ))
#endif

#endif

#else

#ifndef _CRABC_STDDEF_H
#define _CRABC_STDDEF_H

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#elif !defined(NULL)
#define NULL ((void *)0)
#endif
/* Keep the fundamental typedefs shareable with headers such as sys/types.h.
 * Pulling this header into every system header would also leak NULL and
 * offsetof into namespaces where POSIX does not put them. */
#ifndef __DEFINED_size_t
#define __DEFINED_size_t
typedef __SIZE_TYPE__ size_t;
#endif
#ifndef __DEFINED_ptrdiff_t
#define __DEFINED_ptrdiff_t
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif
#ifndef __cplusplus
#ifndef __DEFINED_wchar_t
#define __DEFINED_wchar_t
typedef __WCHAR_TYPE__ wchar_t;
#endif
#endif
#if __STDC_VERSION__ >= 201112L || __cplusplus >= 201103L
typedef struct { long long __max_align_ll; long double __max_align_ld; } max_align_t;
#endif
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif

#endif
