#ifdef CRABC_LRAND48_MUSL_STDLIB
#define _XOPEN_SOURCE 700
#include <stdlib.h>
#else
#include <lrand48.h>
#endif
typedef long (*l0)(void); typedef long (*l1)(unsigned short *); typedef double (*d0)(void); typedef double (*d1)(unsigned short *); typedef void (*v1s)(unsigned short *); typedef void (*v1l)(long); typedef unsigned short *(*seed)(unsigned short *);
_Static_assert(__builtin_types_compatible_p(__typeof__(&lrand48),l0),"lrand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&mrand48),l0),"mrand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&nrand48),l1),"nrand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&jrand48),l1),"jrand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&drand48),d0),"drand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&erand48),d1),"erand48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&seed48),seed),"seed48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&lcong48),v1s),"lcong48"); _Static_assert(__builtin_types_compatible_p(__typeof__(&srand48),v1l),"srand48");
static void *const references[] __attribute__((used)) = {(void *)lrand48, (void *)mrand48, (void *)nrand48, (void *)jrand48, (void *)drand48, (void *)erand48, (void *)seed48, (void *)lcong48, (void *)srand48};
