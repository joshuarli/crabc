/* Static Linux/x86-64 gettid C ABI and behavior fixture.
 *
 * The same GNU project-header C body first executes through pinned musl 1.2.6
 * and then through a true one-member `-nostdlib -static` crabc candidate. It
 * observes only the calling task's positive identifier and compares it with a
 * fixture-local raw gettid syscall. It does not select process identity,
 * scheduler policy, pthread/TCB state, errno, or any other C runtime API.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

_Static_assert(sizeof(pid_t) == 4, "Linux/x86-64 pid_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettid),
    pid_t (*)(void)), "gettid declaration");

typedef pid_t (*gettid_signature)(void);

static pid_t raw_linux_gettid(void)
{
    long result;

    __asm__ volatile (
        "syscall"
        : "=a" (result)
        : "a" (186L)
        : "rcx", "r11", "memory"
    );
    return (pid_t)result;
}

int crabc_x86_64_gettid_probe(void)
{
    const gettid_signature function = gettid;
    pid_t direct = gettid();
    pid_t indirect = function();
    pid_t raw = raw_linux_gettid();

    if (direct <= 0)
        return 1;
    if (indirect != direct)
        return 2;
    if (raw <= 0)
        return 3;
    if (raw != direct)
        return 4;
    return 0;
}

#ifndef CRABC_GETTID_FREESTANDING
int main(void)
{
    return crabc_x86_64_gettid_probe();
}
#endif
