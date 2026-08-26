/* Pinned-musl Linux/x86-64 uname/sysinfo ABI and behavior reference. */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

_Static_assert(sizeof(struct utsname) == 390, "x86 utsname size");
_Static_assert(_Alignof(struct utsname) == 1, "x86 utsname alignment");
_Static_assert(offsetof(struct utsname, machine) == 260, "x86 utsname machine offset");
/* musl's public C record retains its 256-byte compatibility tail, while the
 * Linux syscall writes only the 112-byte prefix owned by crabc-core. */
_Static_assert(sizeof(struct sysinfo) == 368, "x86 public sysinfo size");
_Static_assert(_Alignof(struct sysinfo) == 8, "x86 sysinfo alignment");
_Static_assert(offsetof(struct sysinfo, uptime) == 0, "x86 sysinfo uptime offset");
_Static_assert(offsetof(struct sysinfo, loads) == 8, "x86 sysinfo loads offset");
_Static_assert(offsetof(struct sysinfo, procs) == 80, "x86 sysinfo procs offset");
_Static_assert(offsetof(struct sysinfo, totalhigh) == 88, "x86 sysinfo high-memory offset");
_Static_assert(offsetof(struct sysinfo, mem_unit) == 104, "x86 sysinfo unit offset");
_Static_assert(offsetof(struct sysinfo, __reserved) == 108,
    "x86 sysinfo kernel-prefix end");

int main(void)
{
    struct utsname name;
    struct sysinfo info;

    if (uname(&name) != 0 || sysinfo(&info) != 0)
        return 1;
    if (strcmp(name.sysname, "Linux") != 0 || name.machine[0] == '\0' ||
        info.uptime < 0 || info.procs == 0)
        return 2;

    puts("uname=linux sysinfo=initialized");
    return 0;
}
