/* Static C sync differential over the void Linux request boundary.
 *
 * One project-header C fixture first runs through pinned musl 1.2.6 and then
 * through a true selected-member static crabc-libc candidate. The separate
 * reference fixture supplies the disposable dirty regular-file witness; this
 * freestanding body proves only direct and function-pointer void calls return
 * and that raw Linux sync=162 returns zero. It selects no pathname opening,
 * descriptor synchronization, writeback schedule, durability policy, errno,
 * TLS, allocation, CRT, loader, sysroot, or public x86 support.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef void (*sync_signature)(void);

_Static_assert(SYS_sync == 162, "x86 sync syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync), sync_signature),
               "sync declaration");

static volatile uint32_t sync_calls;

static long raw0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number) : "rcx", "r11", "memory");
    return result;
}

int crabc_x86_64_sync_probe(void)
{
    sync_signature through_pointer = sync;

    sync();
    if (++sync_calls != 1)
        return 10;
    through_pointer();
    if (++sync_calls != 2)
        return 11;
    if (raw0(SYS_sync) != 0)
        return 12;
    return 0;
}

#ifndef CRABC_SYNC_FREESTANDING
int main(void)
{
    return crabc_x86_64_sync_probe();
}
#endif
