#ifndef _CRABC_STDDEF_H
#define _CRABC_STDDEF_H

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#elif !defined(NULL)
#define NULL ((void *)0)
#endif
typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#ifndef __cplusplus
typedef __WCHAR_TYPE__ wchar_t;
#endif
#if __STDC_VERSION__ >= 201112L || __cplusplus >= 201103L
typedef struct { long long __max_align_ll; long double __max_align_ld; } max_align_t;
#endif
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif
