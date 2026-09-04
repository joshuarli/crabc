/* Direct Linux/x86-64 <sched.h> cpu_set_t source/visibility witness. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

#if defined(CRABC_EXPECT_CPU_SET_VISIBLE)
#ifndef CPU_SETSIZE
#error "GNU <sched.h> must expose CPU_SETSIZE with cpu_set_t"
#endif

_Static_assert(sizeof(cpu_set_t) == 128, "musl cpu_set_t width");
_Static_assert(_Alignof(cpu_set_t) == _Alignof(unsigned long),
    "musl cpu_set_t alignment");
_Static_assert(__builtin_offsetof(cpu_set_t, __bits) == 0,
    "musl cpu_set_t storage offset");
_Static_assert(sizeof(((cpu_set_t *)0)->__bits) == 16 * sizeof(unsigned long),
    "musl cpu_set_t storage count");
_Static_assert(CPU_SETSIZE == 1024, "musl CPU_SETSIZE");

int crabc_x86_sched_cpu_set_source_form_probe(void)
{
    return sizeof(cpu_set_t) == 128 ? 0 : 1;
}
#elif defined(CRABC_REQUIRE_CPU_SET_HIDDEN)
#ifdef CPU_SETSIZE
#error "CPU-set surface escaped its GNU profile"
#endif

/* This must fail to form outside the GNU feature block. */
cpu_set_t crabc_x86_sched_cpu_set_must_be_hidden;
#else
#error "the runner must select a cpu_set_t visibility expectation"
#endif
