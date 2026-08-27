/* Pinned-musl Linux/x86-64 umask ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(SYS_umask == 95, "x86 umask syscall number");
_Static_assert(sizeof(mode_t) == sizeof(uint32_t), "x86 mode_t width");
_Static_assert((mode_t)-1 > (mode_t)0, "x86 mode_t is unsigned");
_Static_assert(S_IRUSR == 0400, "owner read mode bit");
_Static_assert(S_IWUSR == 0200, "owner write mode bit");
_Static_assert(S_IRGRP == 0040, "group read mode bit");
_Static_assert(S_IROTH == 0004, "other read mode bit");

static int verify_mask_exchange(void)
{
    const mode_t requested = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    const long original = syscall(SYS_umask, 0UL);

    if (original < 0 || original > 0777)
        return 10;
    if (umask(requested) != 0)
        return 11;
    if (syscall(SYS_umask, 0UL) != (long)requested)
        return 12;
    if (syscall(SYS_umask, (unsigned long)original) != 0)
        return 13;
    return 0;
}

static int run_in_child(void)
{
    const pid_t child = fork();
    int status;

    if (child < 0)
        return 20;
    if (child == 0)
        _exit(verify_mask_exchange());
    if (waitpid(child, &status, 0) != child)
        return 21;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 22;
    return 0;
}

int main(void)
{
    if (run_in_child() != 0)
        return 1;

    puts("umask=95 mode_t=unsigned32 lifecycle=raw-zero:musl-mask:raw-zero:restore child-contained");
    return 0;
}
