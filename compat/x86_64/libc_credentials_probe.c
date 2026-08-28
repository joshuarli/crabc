/* Static crabc-libc x86-64 credential compatibility fixture.
 *
 * The same C body first runs against pinned musl 1.2.6 and then against the
 * selected freestanding crabc static archive. The candidate entry shim
 * supplies the one initial-TLS errno slot required by the archive; it is not
 * a general CRT, pthread/TLS, dynamic-loader, or application-startup claim.
 *
 * Every observed call is non-mutating: the direct setres calls use Linux's
 * all-ones no-change words, while setuid/setgid/setgroups use inputs that the
 * kernel rejects before a credential transition. The four aliases with an
 * intentionally narrower crabc profile are compared as an explicit musl
 * difference, never as an accidental raw-kernel failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t width");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "x86 uid_t width");
_Static_assert(sizeof(gid_t) == sizeof(uint32_t), "x86 gid_t width");
_Static_assert(_Alignof(uid_t) == _Alignof(uint32_t), "x86 uid_t alignment");
_Static_assert(_Alignof(gid_t) == _Alignof(uint32_t), "x86 gid_t alignment");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
_Static_assert(SYS_setuid == 105, "x86 setuid syscall number");
_Static_assert(SYS_setgid == 106, "x86 setgid syscall number");
_Static_assert(SYS_setgroups == 116, "x86 setgroups syscall number");
_Static_assert(SYS_setresuid == 117, "x86 setresuid syscall number");
_Static_assert(SYS_getresuid == 118, "x86 getresuid syscall number");
_Static_assert(SYS_setresgid == 119, "x86 setresgid syscall number");
_Static_assert(SYS_getresgid == 120, "x86 getresgid syscall number");

struct credential_state {
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;
    gid_t real_gid;
    gid_t effective_gid;
    gid_t saved_gid;
};

static long raw_syscall3(long number, long argument1, long argument2,
                         long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static int capture_state(struct credential_state *state)
{
    if (raw_syscall3(SYS_getresuid, (long)&state->real_uid,
                     (long)&state->effective_uid, (long)&state->saved_uid) != 0)
        return -1;
    if (raw_syscall3(SYS_getresgid, (long)&state->real_gid,
                     (long)&state->effective_gid, (long)&state->saved_gid) != 0)
        return -1;
    return 0;
}

static int same_state(const struct credential_state *expected)
{
    struct credential_state observed;

    if (capture_state(&observed) != 0)
        return 0;
    return observed.real_uid == expected->real_uid &&
           observed.effective_uid == expected->effective_uid &&
           observed.saved_uid == expected->saved_uid &&
           observed.real_gid == expected->real_gid &&
           observed.effective_gid == expected->effective_gid &&
           observed.saved_gid == expected->saved_gid;
}

static int check_direct_no_change(const struct credential_state *before)
{
    if (setresuid(UINT32_MAX, UINT32_MAX, UINT32_MAX) != 0 ||
        !same_state(before))
        return 1;
    if (setresgid(UINT32_MAX, UINT32_MAX, UINT32_MAX) != 0 ||
        !same_state(before))
        return 2;
    return 0;
}

static int check_rejected_inputs(const struct credential_state *before)
{
    errno = 0;
    if (setuid(UINT32_MAX) != -1 || errno != EINVAL || !same_state(before))
        return 1;
    errno = 0;
    if (setgid(UINT32_MAX) != -1 || errno != EINVAL || !same_state(before))
        return 2;
    errno = 0;
    if (setgroups((size_t)-1, NULL) != -1 || errno != EINVAL ||
        !same_state(before))
        return 3;
    return 0;
}

static int check_profile_aliases(const struct credential_state *before)
{
#if defined(CRABC_CREDENTIAL_PROFILE)
    errno = 0;
    if (setreuid((uid_t)-1, before->effective_uid) != -1 ||
        errno != EOPNOTSUPP || !same_state(before))
        return 1;
    errno = 0;
    if (seteuid(before->effective_uid) != -1 || errno != EOPNOTSUPP ||
        !same_state(before))
        return 2;
    errno = 0;
    if (setregid((gid_t)-1, before->effective_gid) != -1 ||
        errno != EOPNOTSUPP || !same_state(before))
        return 3;
    errno = 0;
    if (setegid(before->effective_gid) != -1 || errno != EOPNOTSUPP ||
        !same_state(before))
        return 4;
#else
    if (setreuid((uid_t)-1, before->effective_uid) != 0 || !same_state(before))
        return 1;
    if (seteuid(before->effective_uid) != 0 || !same_state(before))
        return 2;
    if (setregid((gid_t)-1, before->effective_gid) != 0 || !same_state(before))
        return 3;
    if (setegid(before->effective_gid) != 0 || !same_state(before))
        return 4;
#endif
    return 0;
}

int crabc_x86_64_credentials_probe(void)
{
    struct credential_state before;
    int status;

    if (capture_state(&before) != 0)
        return 1;
    status = check_direct_no_change(&before);
    if (status != 0)
        return 10 + status;
    status = check_rejected_inputs(&before);
    if (status != 0)
        return 20 + status;
    status = check_profile_aliases(&before);
    if (status != 0)
        return 30 + status;
    return 0;
}

#ifndef CRABC_CREDENTIAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_credentials_probe();
}
#endif
