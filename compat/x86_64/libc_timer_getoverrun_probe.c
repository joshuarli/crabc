/* Static crabc-libc x86-64 selected timer_getoverrun error-ABI fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate. It passes only
 * nonnegative opaque timer bits that cannot name a process timer, so it never
 * creates, arms, queries, deletes, or otherwise observes a valid POSIX timer.
 * It observes ordinary C -1/errno conversion only, not timer state, overrun
 * values, tagged pthread timer IDs, signal delivery, or timer policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

typedef int (*timer_getoverrun_signature)(timer_t);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(timer_t) == 8 && _Alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
_Static_assert(SYS_timer_getoverrun == 225,
    "x86 timer_getoverrun syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timer_getoverrun),
    timer_getoverrun_signature), "timer_getoverrun declaration");

static volatile timer_getoverrun_signature timer_getoverrun_function =
    timer_getoverrun;

static int check_rejected_timer(timer_t timer, int sentinel)
{
    errno = sentinel;
    if (timer_getoverrun_function(timer) != -1 || errno != EINVAL)
        return 1;
    return 0;
}

int crabc_x86_64_timer_getoverrun_probe(void)
{
    int status = check_rejected_timer((timer_t)0, ERANGE);

    if (status != 0)
        return 10 + status;
    status = check_rejected_timer((timer_t)(uintptr_t)INT_MAX, E2BIG);
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_TIMER_GETOVERRUN_FREESTANDING
int main(void)
{
    return crabc_x86_64_timer_getoverrun_probe();
}
#endif
