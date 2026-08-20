#ifndef _ASSERT_H
#define _ASSERT_H

#include <features.h>

#ifdef NDEBUG
#define assert(expression) ((void)0)
#else
void __assert_fail(const char *, const char *, int, const char *) __attribute__((__noreturn__));
#define assert(expression) ((expression) ? (void)0 : __assert_fail(#expression, __FILE__, __LINE__, __func__))
#endif

#if __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
#define static_assert _Static_assert
#endif

#endif
