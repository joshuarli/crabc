#ifdef CRABC_LRAND48_MUSL_STDLIB
#define _XOPEN_SOURCE 700
#include <stdlib.h>
#else
#include <lrand48.h>
#endif
using l0=long(*)(void); using l1=long(*)(unsigned short*); using d0=double(*)(void); using d1=double(*)(unsigned short*); using v1s=void(*)(unsigned short*); using v1l=void(*)(long); using seed=unsigned short*(*)(unsigned short*);
static_assert(__is_same(decltype(&lrand48),l0)); static_assert(__is_same(decltype(&mrand48),l0)); static_assert(__is_same(decltype(&nrand48),l1)); static_assert(__is_same(decltype(&jrand48),l1)); static_assert(__is_same(decltype(&drand48),d0)); static_assert(__is_same(decltype(&erand48),d1)); static_assert(__is_same(decltype(&seed48),seed)); static_assert(__is_same(decltype(&lcong48),v1s)); static_assert(__is_same(decltype(&srand48),v1l));
static void *const references[] __attribute__((used)) = {(void *)lrand48, (void *)mrand48, (void *)nrand48, (void *)jrand48, (void *)drand48, (void *)erand48, (void *)seed48, (void *)lcong48, (void *)srand48};
