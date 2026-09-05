/* Installed x86-64 credential-profile differential.
 *
 * The selected profile owns nine setters. Five are direct, caller-coordinated
 * Linux operations; four historical aliases deliberately report EOPNOTSUPP
 * without an ID transition. This consumer does not invent musl's all-thread
 * credential rendezvous. It starts with no application workers and performs
 * each call in a fresh child of the disposable user-namespace process.
 *
 * The direct subcase exercises successful explicit current-ID calls for every
 * direct uid/gid setter, plus Linux's all-ones no-change words for setresuid
 * and setresgid and unmapped-ID rejection for setuid/setgid. The mapped user
 * namespace deliberately denies setgroups; that call supplies a valid live
 * one-element gid_t slice and expects EPERM before any ID transition. Every
 * child records its raw status and errno with real/effective/saved IDs before
 * and after the call. The aliases use unchanged IDs too: musl succeeds, while
 * crabc's selected profile must return -1/EOPNOTSUPP. The runner keeps those
 * intentional alias transcripts separate from the raw-equivalent direct
 * differential.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "credentials profile requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <grp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t width");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "x86 uid_t width");
_Static_assert(sizeof(gid_t) == sizeof(uint32_t), "x86 gid_t width");
_Static_assert(_Alignof(uid_t) == _Alignof(uint32_t), "x86 uid_t alignment");
_Static_assert(_Alignof(gid_t) == _Alignof(uint32_t), "x86 gid_t alignment");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
_Static_assert(SYS_getresuid == 118, "x86 getresuid syscall number");
_Static_assert(SYS_getresgid == 120, "x86 getresgid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setgroups),
    int (*)(size_t, const gid_t *)), "setgroups declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setuid), int (*)(uid_t)),
    "setuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setgid), int (*)(gid_t)),
    "setgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setresuid),
    int (*)(uid_t, uid_t, uid_t)), "setresuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setresgid),
    int (*)(gid_t, gid_t, gid_t)), "setresgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&seteuid), int (*)(uid_t)),
    "seteuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setegid), int (*)(gid_t)),
    "setegid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setreuid),
    int (*)(uid_t, uid_t)), "setreuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setregid),
    int (*)(gid_t, gid_t)), "setregid declaration");

struct credential_ids {
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;
    gid_t real_gid;
    gid_t effective_gid;
    gid_t saved_gid;
};

struct credential_result {
    int status;
    int error;
};

typedef int (*credential_case)(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result);

struct named_credential_case {
    const char *name;
    credential_case call;
};

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static int capture_ids(struct credential_ids *ids)
{
    if (raw_syscall3(SYS_getresuid, (long)&ids->real_uid,
            (long)&ids->effective_uid, (long)&ids->saved_uid) != 0)
        return 0;
    if (raw_syscall3(SYS_getresgid, (long)&ids->real_gid,
            (long)&ids->effective_gid, (long)&ids->saved_gid) != 0)
        return 0;
    return 1;
}

static int ids_unchanged(const struct credential_ids *before,
    const struct credential_ids *after)
{
    return after->real_uid == before->real_uid &&
        after->effective_uid == before->effective_uid &&
        after->saved_uid == before->saved_uid &&
        after->real_gid == before->real_gid &&
        after->effective_gid == before->effective_gid &&
        after->saved_gid == before->saved_gid;
}

static int direct_current_resuid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setresuid(before->real_uid, before->effective_uid,
        before->saved_uid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_resgid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setresgid(before->real_gid, before->effective_gid,
        before->saved_gid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_uid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setuid(before->effective_uid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_gid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setgid(before->effective_gid);
    result->error = errno;
    return result->status == 0;
}

static int direct_no_change_resuid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)before;
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setresuid(UINT32_MAX, UINT32_MAX, UINT32_MAX);
    result->error = errno;
    return result->status == 0;
}

static int direct_no_change_resgid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)before;
    (void)profile_aliases;
    errno = ERANGE;
    result->status = setresgid(UINT32_MAX, UINT32_MAX, UINT32_MAX);
    result->error = errno;
    return result->status == 0;
}

static int direct_rejected_uid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)before;
    (void)profile_aliases;
    errno = 0;
    result->status = setuid(UINT32_MAX);
    result->error = errno;
    return result->status == -1 && result->error == EINVAL;
}

static int direct_rejected_gid(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    (void)before;
    (void)profile_aliases;
    errno = 0;
    result->status = setgid(UINT32_MAX);
    result->error = errno;
    return result->status == -1 && result->error == EINVAL;
}

static int direct_rejected_groups(const struct credential_ids *before,
    int profile_aliases, struct credential_result *result)
{
    gid_t groups[1] = { before->effective_gid };

    (void)profile_aliases;
    errno = 0;
    result->status = setgroups(1, groups);
    result->error = errno;
    return result->status == -1 && result->error == EPERM;
}

static int alias_setreuid(const struct credential_ids *before, int profile_aliases,
    struct credential_result *result)
{
    errno = 0;
    result->status = setreuid((uid_t)-1, before->effective_uid);
    result->error = errno;
    if (profile_aliases)
        return result->status == -1 && result->error == EOPNOTSUPP;
    return result->status == 0;
}

static int alias_seteuid(const struct credential_ids *before, int profile_aliases,
    struct credential_result *result)
{
    errno = 0;
    result->status = seteuid(before->effective_uid);
    result->error = errno;
    if (profile_aliases)
        return result->status == -1 && result->error == EOPNOTSUPP;
    return result->status == 0;
}

static int alias_setregid(const struct credential_ids *before, int profile_aliases,
    struct credential_result *result)
{
    errno = 0;
    result->status = setregid((gid_t)-1, before->effective_gid);
    result->error = errno;
    if (profile_aliases)
        return result->status == -1 && result->error == EOPNOTSUPP;
    return result->status == 0;
}

static int alias_setegid(const struct credential_ids *before, int profile_aliases,
    struct credential_result *result)
{
    errno = 0;
    result->status = setegid(before->effective_gid);
    result->error = errno;
    if (profile_aliases)
        return result->status == -1 && result->error == EOPNOTSUPP;
    return result->status == 0;
}

static void print_case(const char *scenario, const char *name,
    const struct credential_result *result, const struct credential_ids *before,
    const struct credential_ids *after)
{
    printf("credentials-profile %s %s: status=%d errno=%d "
        "before=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu "
        "after=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu ids=unchanged\n",
        scenario, name, result->status, result->error,
        (unsigned long)before->real_uid, (unsigned long)before->effective_uid,
        (unsigned long)before->saved_uid, (unsigned long)before->real_gid,
        (unsigned long)before->effective_gid, (unsigned long)before->saved_gid,
        (unsigned long)after->real_uid, (unsigned long)after->effective_uid,
        (unsigned long)after->saved_uid, (unsigned long)after->real_gid,
        (unsigned long)after->effective_gid, (unsigned long)after->saved_gid);
    fflush(stdout);
}

static int run_private_case(const char *scenario,
    const struct named_credential_case *entry, int profile_aliases)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        struct credential_ids before = { 0 };
        struct credential_ids after = { 0 };
        struct credential_result result = { -1, 0 };
        int before_ok = capture_ids(&before);
        int call_ok = before_ok && entry->call(&before, profile_aliases, &result);
        int after_ok = capture_ids(&after);

        if (before_ok && after_ok)
            print_case(scenario, entry->name, &result, &before, &after);
        _exit(before_ok && call_ok && after_ok && ids_unchanged(&before, &after)
            ? 0 : 1);
    }
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0;
}

static int run_cases(const char *scenario,
    const struct named_credential_case *cases, size_t count, int profile_aliases)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (!run_private_case(scenario, &cases[index], profile_aliases))
            return 0;
    return 1;
}

static int equals(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const struct named_credential_case direct_cases[] = {
        { "setresuid-current", direct_current_resuid },
        { "setresgid-current", direct_current_resgid },
        { "setuid-current", direct_current_uid },
        { "setgid-current", direct_current_gid },
        { "setresuid-all-ones", direct_no_change_resuid },
        { "setresgid-all-ones", direct_no_change_resgid },
        { "setuid-unmapped", direct_rejected_uid },
        { "setgid-unmapped", direct_rejected_gid },
        { "setgroups-current", direct_rejected_groups },
    };
    static const struct named_credential_case alias_cases[] = {
        { "setreuid-current", alias_setreuid },
        { "seteuid-current", alias_seteuid },
        { "setregid-current", alias_setregid },
        { "setegid-current", alias_setegid },
    };

    if (argc != 2)
        return 64;
    if (equals(argv[1], "direct")) {
        if (!run_cases("direct", direct_cases,
                sizeof(direct_cases) / sizeof(*direct_cases), 0))
            return 1;
        puts("credentials-profile direct: successful-current/no-change/rejected IDs-unchanged");
        return 0;
    }
    if (equals(argv[1], "aliases-musl")) {
        if (!run_cases("aliases-musl", alias_cases,
                sizeof(alias_cases) / sizeof(*alias_cases), 0))
            return 2;
        puts("credentials-profile aliases: musl-success IDs-unchanged");
        return 0;
    }
    if (equals(argv[1], "aliases-profile")) {
        if (!run_cases("aliases-profile", alias_cases,
                sizeof(alias_cases) / sizeof(*alias_cases), 1))
            return 3;
        puts("credentials-profile aliases: crabc-eopnotsupp IDs-unchanged");
        return 0;
    }
    return 64;
}
