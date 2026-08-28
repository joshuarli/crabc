/* Static crabc-libc x86-64 credential-observation compatibility fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. It observes the
 * calling process's supplementary groups and real/effective/saved identity
 * triples only; it neither changes credentials nor consults account files.
 *
 * getgroups intentionally has no stable-snapshot guarantee: a caller must
 * retry when its count-to-fill window observes EINVAL. The bounded loop
 * retains that retry policy without inducing a concurrent credential change.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    /* Linux 5.10's supplementary-group ceiling, plus one trailing sentinel. */
    GROUP_STORAGE_CAPACITY = 65536,
    GROUP_CAPTURE_ATTEMPTS = 4,
};

_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4,
    "x86 uid_t ABI");
_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4,
    "x86 gid_t ABI");
_Static_assert((uid_t)-1 > (uid_t)0 && (gid_t)-1 > (gid_t)0,
    "x86 credential scalar unsignedness");
_Static_assert(SYS_getgroups == 115 && SYS_getresuid == 118 &&
    SYS_getresgid == 120, "x86 credential-observation syscall numbers");

struct user_identity {
    uid_t real;
    uid_t effective;
    uid_t saved;
};

struct group_identity {
    gid_t real;
    gid_t effective;
    gid_t saved;
};

static gid_t observed_groups[GROUP_STORAGE_CAPACITY + 1];

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

static int user_identities_equal(const struct user_identity *left,
                                 const struct user_identity *right)
{
    return left->real == right->real &&
        left->effective == right->effective && left->saved == right->saved;
}

static int group_identities_equal(const struct group_identity *left,
                                  const struct group_identity *right)
{
    return left->real == right->real &&
        left->effective == right->effective && left->saved == right->saved;
}

static uid_t user_identity_sentinel(const struct user_identity *identity)
{
    uid_t sentinel = UINT32_C(0xa5c35a3c);

    while (sentinel == identity->real || sentinel == identity->effective ||
           sentinel == identity->saved)
        ++sentinel;
    return sentinel;
}

static gid_t group_identity_sentinel(const struct group_identity *identity)
{
    gid_t sentinel = UINT32_C(0x3ca55ac3);

    while (sentinel == identity->real || sentinel == identity->effective ||
           sentinel == identity->saved)
        ++sentinel;
    return sentinel;
}

static int check_groups(void)
{
    unsigned int attempt;

    errno = 0;
    if (getgroups(-1, observed_groups) != -1 || errno != EINVAL)
        return 1;

    for (attempt = 0; attempt < GROUP_CAPTURE_ATTEMPTS; ++attempt) {
        int count;
        int filled;

        errno = 0;
        count = getgroups(0, NULL);
        if (count < 0 || count > GROUP_STORAGE_CAPACITY)
            return 2;

        observed_groups[count] = UINT32_C(0xa5c35a3c);
        errno = 0;
        filled = getgroups(count, observed_groups);
        if (filled == count) {
            int undersized;

            if (observed_groups[count] != UINT32_C(0xa5c35a3c))
                return 3;
            if (count == 0)
                return 0;

            errno = 0;
            undersized = getgroups(count - 1, observed_groups);
            if (undersized == -1 && errno == EINVAL)
                return 0;
            /* A concurrent credential transition may have shrunk the list. */
            if (undersized >= 0 && undersized <= count - 1)
                continue;
            return 4;
        }
        /* A concurrent credential transition may have grown the list. */
        if (filled == -1 && errno == EINVAL)
            continue;
        return 5;
    }
    return 6;
}

static int check_user_partial_fault_order(const struct user_identity *identity)
{
    uid_t sentinel = user_identity_sentinel(identity);
    unsigned int valid_mask;

    /*
     * Linux writes getresuid outputs in pointer order until a null pointer
     * faults. Comparing each raw partial-fault pattern with the candidate
     * proves the rdi/rsi/rdx mapping even when all three current IDs match.
     */
    for (valid_mask = 0; valid_mask < 8; ++valid_mask) {
        struct user_identity direct = { sentinel, sentinel, sentinel };
        struct user_identity observed = { sentinel, sentinel, sentinel };
        uid_t *direct_real = valid_mask & 1u ? &direct.real : NULL;
        uid_t *direct_effective = valid_mask & 2u ? &direct.effective : NULL;
        uid_t *direct_saved = valid_mask & 4u ? &direct.saved : NULL;
        uid_t *observed_real = valid_mask & 1u ? &observed.real : NULL;
        uid_t *observed_effective =
            valid_mask & 2u ? &observed.effective : NULL;
        uid_t *observed_saved = valid_mask & 4u ? &observed.saved : NULL;
        long direct_status = raw_syscall3(SYS_getresuid, (long)direct_real,
            (long)direct_effective, (long)direct_saved);
        int observed_status;

        if (direct_status != 0 && direct_status != -EFAULT)
            return 1;
        errno = 0;
        observed_status = getresuid(observed_real, observed_effective,
            observed_saved);
        if (direct_status == 0) {
            if (observed_status != 0)
                return 2;
        } else if (observed_status != -1 || errno != EFAULT) {
            return 3;
        }
        if (!user_identities_equal(&direct, &observed))
            return 4;
    }
    return 0;
}

static int check_group_partial_fault_order(const struct group_identity *identity)
{
    gid_t sentinel = group_identity_sentinel(identity);
    unsigned int valid_mask;

    /* See check_user_partial_fault_order for why all eight patterns matter. */
    for (valid_mask = 0; valid_mask < 8; ++valid_mask) {
        struct group_identity direct = { sentinel, sentinel, sentinel };
        struct group_identity observed = { sentinel, sentinel, sentinel };
        gid_t *direct_real = valid_mask & 1u ? &direct.real : NULL;
        gid_t *direct_effective = valid_mask & 2u ? &direct.effective : NULL;
        gid_t *direct_saved = valid_mask & 4u ? &direct.saved : NULL;
        gid_t *observed_real = valid_mask & 1u ? &observed.real : NULL;
        gid_t *observed_effective =
            valid_mask & 2u ? &observed.effective : NULL;
        gid_t *observed_saved = valid_mask & 4u ? &observed.saved : NULL;
        long direct_status = raw_syscall3(SYS_getresgid, (long)direct_real,
            (long)direct_effective, (long)direct_saved);
        int observed_status;

        if (direct_status != 0 && direct_status != -EFAULT)
            return 1;
        errno = 0;
        observed_status = getresgid(observed_real, observed_effective,
            observed_saved);
        if (direct_status == 0) {
            if (observed_status != 0)
                return 2;
        } else if (observed_status != -1 || errno != EFAULT) {
            return 3;
        }
        if (!group_identities_equal(&direct, &observed))
            return 4;
    }
    return 0;
}

static int check_user_identity(void)
{
    struct user_identity direct;
    struct user_identity observed;

    if (raw_syscall3(SYS_getresuid, (long)&direct.real,
                     (long)&direct.effective, (long)&direct.saved) != 0)
        return 1;
    errno = 0;
    if (getresuid(&observed.real, &observed.effective, &observed.saved) != 0 ||
        observed.real != direct.real || observed.effective != direct.effective ||
        observed.saved != direct.saved)
        return 2;
    errno = 0;
    if (getresuid(NULL, NULL, NULL) != -1 || errno != EFAULT)
        return 3;
    if (check_user_partial_fault_order(&direct) != 0)
        return 4;
    return 0;
}

static int check_group_identity(void)
{
    struct group_identity direct;
    struct group_identity observed;

    if (raw_syscall3(SYS_getresgid, (long)&direct.real,
                     (long)&direct.effective, (long)&direct.saved) != 0)
        return 1;
    errno = 0;
    if (getresgid(&observed.real, &observed.effective, &observed.saved) != 0 ||
        observed.real != direct.real || observed.effective != direct.effective ||
        observed.saved != direct.saved)
        return 2;
    errno = 0;
    if (getresgid(NULL, NULL, NULL) != -1 || errno != EFAULT)
        return 3;
    if (check_group_partial_fault_order(&direct) != 0)
        return 4;
    return 0;
}

int crabc_x86_64_credential_observation_probe(void)
{
    int status = check_groups();

    if (status != 0)
        return 10 + status;
    status = check_user_identity();
    if (status != 0)
        return 20 + status;
    status = check_group_identity();
    return status == 0 ? 0 : 30 + status;
}

#ifndef CRABC_CREDENTIAL_OBSERVATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_credential_observation_probe();
}
#endif
