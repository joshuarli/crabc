/* Static crabc-libc x86-64 bounded pthread task-name fixture.
 *
 * The same GNU project-header C body first runs against pinned musl 1.2.6,
 * then through a dependency-free -nostdlib -static candidate linked only with
 * the selected crabc archive. It proves only pthread_setname_np and
 * pthread_getname_np for the bootstrapped process-main pthread_self() handle:
 * Linux's sixteen-byte task-comm state changes through PR_SET_NAME and is
 * observed both through the paired pthread getter and raw PR_GET_NAME.
 * Candidate-only non-self handles fail closed with ESRCH before input/output
 * observation. This does not select workers, a TCB/thread list, /proc task
 * naming, cancellation, a general prctl C API, scheduler/affinity attributes,
 * lifecycle, synchronization, TSS, CRT, loader, sysroot, general pthread/TLS
 * behavior, or public x86 support.
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
#include <pthread.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define CRABC_TASK_COMM_LEN 16

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_prctl == 157,
    "x86 pthread-name fixture uses prctl=157");
_Static_assert(PR_SET_NAME == 15 && PR_GET_NAME == 16,
    "Linux task-name prctl options");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_setname_np),
    int (*)(pthread_t, const char *)), "pthread_setname_np declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getname_np),
    int (*)(pthread_t, char *, size_t)), "pthread_getname_np declaration");

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_get_name(char name[CRABC_TASK_COMM_LEN])
{
    return raw_syscall5(SYS_prctl, PR_GET_NAME, (long)(uintptr_t)name,
        0, 0, 0) == 0 ? 0 : -1;
}

static int name_has_prefix_and_nul(const char name[CRABC_TASK_COMM_LEN],
    const char *expected)
{
    unsigned index;

    for (index = 0; index < CRABC_TASK_COMM_LEN; index++) {
        if (expected[index] == '\0')
            return name[index] == '\0';
        if (name[index] != expected[index])
            return 0;
    }
    return 0;
}

static void fill_bytes(char *destination, unsigned count, char value)
{
    unsigned index;

    for (index = 0; index < count; index++)
        destination[index] = value;
}

static int bytes_are(const char *value, unsigned count, char expected)
{
    unsigned index;

    for (index = 0; index < count; index++)
        if (value[index] != expected)
            return 0;
    return 1;
}

static int check_self_name_pair(void)
{
    static const char selected_name[] = "crabc-pth-name";
    static const char too_long_name[] = "0123456789abcdef";
    const int preserved_errno = E2BIG;
    pthread_t self = pthread_self();
    char original[CRABC_TASK_COMM_LEN];
    char observed[CRABC_TASK_COMM_LEN];
    char short_name[CRABC_TASK_COMM_LEN - 1];

    if (self == (pthread_t)0)
        return 1;
    if (raw_get_name(original) != 0)
        return 2;

    errno = preserved_errno;
    if (pthread_setname_np(self, selected_name) != 0)
        return 3;
    if (errno != preserved_errno)
        return 4;

    fill_bytes(observed, sizeof(observed), (char)0x5a);
    errno = preserved_errno;
    if (pthread_getname_np(self, observed, sizeof(observed)) != 0)
        return 5;
    if (errno != preserved_errno)
        return 6;
    if (!name_has_prefix_and_nul(observed, selected_name))
        return 7;
    fill_bytes(observed, sizeof(observed), (char)0x5a);
    if (raw_get_name(observed) != 0)
        return 8;
    if (!name_has_prefix_and_nul(observed, selected_name))
        return 9;

    errno = preserved_errno;
    if (pthread_setname_np(self, too_long_name) != ERANGE)
        return 10;
    if (errno != preserved_errno)
        return 11;
    fill_bytes(observed, sizeof(observed), (char)0x5a);
    if (raw_get_name(observed) != 0 || !name_has_prefix_and_nul(observed, selected_name))
        return 12;

    fill_bytes(short_name, sizeof(short_name), (char)0x4a);
    errno = preserved_errno;
    if (pthread_getname_np(self, short_name, sizeof(short_name)) != ERANGE)
        return 13;
    if (errno != preserved_errno)
        return 14;
    if (!bytes_are(short_name, sizeof(short_name), (char)0x4a))
        return 15;

    errno = preserved_errno;
    if (pthread_setname_np(self, original) != 0)
        return 16;
    if (errno != preserved_errno)
        return 17;
    return 0;
}

#if defined(CRABC_PTHREAD_NAME_FREESTANDING)
static int check_candidate_nonself_rejection(void)
{
    static const char too_long_name[] = "0123456789abcdef";
    const int preserved_errno = ERANGE;
    pthread_t foreign = (pthread_t)(uintptr_t)1;
    char output[CRABC_TASK_COMM_LEN];

    errno = preserved_errno;
    if (pthread_setname_np(foreign, too_long_name) != ESRCH)
        return 1;
    if (errno != preserved_errno)
        return 2;

    fill_bytes(output, sizeof(output), (char)0x33);
    errno = preserved_errno;
    if (pthread_getname_np(foreign, output, 1) != ESRCH)
        return 3;
    if (errno != preserved_errno)
        return 4;
    if (!bytes_are(output, sizeof(output), (char)0x33))
        return 5;
    return 0;
}
#endif

int crabc_x86_64_pthread_name_probe(void)
{
    int status = check_self_name_pair();

    if (status != 0)
        return 10 + status;
#if defined(CRABC_PTHREAD_NAME_FREESTANDING)
    status = check_candidate_nonself_rejection();
    if (status != 0)
        return 40 + status;
#endif
    return 0;
}

#ifndef CRABC_PTHREAD_NAME_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_name_probe();
}
#endif
