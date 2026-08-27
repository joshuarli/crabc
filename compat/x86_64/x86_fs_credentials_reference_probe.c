/* Pinned-musl Linux/x86-64 filesystem-credential ABI reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdint.h>
#include <stdio.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(SYS_setfsuid == 122, "x86 setfsuid syscall number");
_Static_assert(SYS_setfsgid == 123, "x86 setfsgid syscall number");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "x86 uid_t width");
_Static_assert(sizeof(gid_t) == sizeof(uint32_t), "x86 gid_t width");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");

static uid_t musl_fsuid_query(void)
{
    /* Linux returns the previous ID even when a requested change is denied. */
    return (uid_t)setfsuid((uid_t)-1);
}

static gid_t musl_fsgid_query(void)
{
    return (gid_t)setfsgid((gid_t)-1);
}

static uid_t raw_fsuid_query(void)
{
    return (uid_t)syscall(SYS_setfsuid, (unsigned long)UINT32_MAX);
}

static gid_t raw_fsgid_query(void)
{
    return (gid_t)syscall(SYS_setfsgid, (unsigned long)UINT32_MAX);
}

static int credentials_case(void)
{
    const uid_t original_uid = musl_fsuid_query();
    const gid_t original_gid = musl_fsgid_query();
    const uid_t effective_uid = geteuid();
    const gid_t effective_gid = getegid();

    if (raw_fsuid_query() != original_uid || raw_fsgid_query() != original_gid)
        return 10;

    if ((uid_t)syscall(SYS_setfsuid, (unsigned long)effective_uid) != original_uid)
        return 11;
    if ((gid_t)syscall(SYS_setfsgid, (unsigned long)effective_gid) != original_gid)
        return 12;
    if (musl_fsuid_query() != effective_uid || musl_fsgid_query() != effective_gid)
        return 13;

    if ((uid_t)setfsuid(effective_uid) != effective_uid ||
        (gid_t)setfsgid(effective_gid) != effective_gid)
        return 14;
    if (raw_fsuid_query() != effective_uid || raw_fsgid_query() != effective_gid)
        return 15;

    return 0;
}

static int run_in_child(void)
{
    const pid_t child = fork();
    int status;

    if (child < 0)
        return 20;
    if (child == 0)
        _exit(credentials_case());
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

    puts("syscalls=setfsuid:122,setfsgid:123 ids=u32 lifecycle=musl-query:raw-query:raw-current:musl-current:raw-query child-contained");
    return 0;
}
