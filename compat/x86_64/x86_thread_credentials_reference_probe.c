/* Pinned-musl Linux/x86-64 calling-thread credential ABI reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(SYS_setresuid == 117, "x86 setresuid syscall number");
_Static_assert(SYS_setresgid == 119, "x86 setresgid syscall number");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "x86 uid_t width");
_Static_assert(sizeof(gid_t) == sizeof(uint32_t), "x86 gid_t width");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");

static int same_ids(
    uid_t before_real,
    uid_t before_effective,
    uid_t before_saved,
    gid_t before_group_real,
    gid_t before_group_effective,
    gid_t before_group_saved)
{
    uid_t real;
    uid_t effective;
    uid_t saved;
    gid_t group_real;
    gid_t group_effective;
    gid_t group_saved;

    if (getresuid(&real, &effective, &saved) != 0 ||
        getresgid(&group_real, &group_effective, &group_saved) != 0)
        return 0;
    return real == before_real && effective == before_effective &&
           saved == before_saved && group_real == before_group_real &&
           group_effective == before_group_effective &&
           group_saved == before_group_saved;
}

int main(void)
{
    uid_t real;
    uid_t effective;
    uid_t saved;
    gid_t group_real;
    gid_t group_effective;
    gid_t group_saved;

    if (getresuid(&real, &effective, &saved) != 0 ||
        getresgid(&group_real, &group_effective, &group_saved) != 0)
        return 10;

    /* Pinned musl's C API must preserve Linux's all-ones no-change words. */
    if (setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) != 0 ||
        setresgid((gid_t)-1, (gid_t)-1, (gid_t)-1) != 0)
        return 11;
    if (!same_ids(real, effective, saved, group_real, group_effective, group_saved))
        return 12;

    /* Confirm the direct x86 three-register syscall boundary independently. */
    if (syscall(SYS_setresuid, UINT32_MAX, UINT32_MAX, UINT32_MAX) != 0 ||
        syscall(SYS_setresgid, UINT32_MAX, UINT32_MAX, UINT32_MAX) != 0)
        return 13;
    if (!same_ids(real, effective, saved, group_real, group_effective, group_saved))
        return 14;

    puts("syscalls=setresuid:117,setresgid:119 ids=u32 no-change=musl+raw stable");
    return 0;
}
