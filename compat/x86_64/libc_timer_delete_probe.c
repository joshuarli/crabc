/* Static crabc-libc x86-64 selected timer_delete raw-error-ABI fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate. In a fresh process
 * that creates no POSIX timers, it passes only nonnegative opaque timer bits
 * 0 and INT_MAX. It proves raw -EINVAL and caller errno preservation only;
 * it neither creates, arms, queries, observes, nor deletes a valid timer.
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

typedef int (*timer_delete_signature)(timer_t);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(timer_t) == 8 && _Alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
_Static_assert(SYS_timer_delete == 226, "x86 timer_delete syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timer_delete),
    timer_delete_signature), "timer_delete declaration");

static volatile timer_delete_signature timer_delete_function = timer_delete;

static int check_raw_rejection(timer_t timer, int sentinel)
{
    errno = sentinel;
    if (timer_delete_function(timer) != -EINVAL || errno != sentinel)
        return 1;
    return 0;
}

int crabc_x86_64_timer_delete_probe(void)
{
    int status = check_raw_rejection((timer_t)0, ERANGE);

    if (status != 0)
        return 10 + status;
    status = check_raw_rejection((timer_t)(uintptr_t)INT_MAX, E2BIG);
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_TIMER_DELETE_FREESTANDING
int main(void)
{
    return crabc_x86_64_timer_delete_probe();
}
#endif
