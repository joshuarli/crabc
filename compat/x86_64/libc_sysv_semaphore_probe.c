/* Native Linux/x86-64 static SysV-semaphore C ABI fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive.  It specifies the useful
 * single-set lifecycle: semget, semctl scalar/pointer unions for
 * SETVAL/GETVAL/SETALL/GETALL/IPC_STAT/IPC_RMID, successful and nonblocking
 * semop, and successful/zero-timeout semtimedop.  It deliberately proves raw
 * Linux errno translation and that successes leave an unrelated errno value
 * intact.  It is not a complete SysV IPC family, multi-process
 * synchronization, SEM_UNDO, IPC_SET, namespace permissions, cancellation,
 * CRT, loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>

/* POSIX intentionally does not own this SysV extension.  Musl and the
 * project header advertise that fact with _SEM_SEMUN_UNDEFINED, leaving the
 * application to provide the ABI union needed for semctl's varargs call. */
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct sembuf) == 6 && _Alignof(struct sembuf) == 2,
    "musl x86-64 struct sembuf ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "musl x86-64 struct timespec ABI");
_Static_assert(IPC_PRIVATE == 0 && IPC_RMID == 0 && IPC_NOWAIT == 04000,
    "Linux SysV IPC command and flag values");
_Static_assert(GETVAL == 12 && GETALL == 13 && SETVAL == 16 && SETALL == 17 &&
    SEM_UNDO == 0x1000,
    "Linux SysV semaphore command and flag values");
_Static_assert(SYS_semget == 64 && SYS_semop == 65 && SYS_semctl == 66 &&
    SYS_semtimedop == 220, "Linux x86-64 SysV semaphore syscall numbers");
_Static_assert(CRABC_TYPE_IS(__typeof__(&semget), int (*)(key_t, int, int)),
    "semget declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&semop),
    int (*)(int, struct sembuf *, size_t)), "semop declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&semtimedop),
    int (*)(int, struct sembuf *, size_t, const struct timespec *)),
    "semtimedop declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&semctl), int (*)(int, int, int, ...)),
    "semctl declaration");

/* The test-only seccomp program below reads `struct seccomp_data` directly.
 * Keep its small BPF ABI private to this fixture: public seccomp headers and
 * a general prctl wrapper are not selected static-C surface.  On x86-64 the
 * kernel lays out the syscall number at byte 0 and args[3] at bytes 40..47.
 * Split the 64-bit fourth syscall argument into two BPF word loads so this
 * regression proves the complete Linux r10 word is zero, not merely its low
 * half. */
struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

enum {
    CRABC_BPF_LD = 0x00,
    CRABC_BPF_W = 0x00,
    CRABC_BPF_ABS = 0x20,
    CRABC_BPF_JMP = 0x05,
    CRABC_BPF_JEQ = 0x10,
    CRABC_BPF_K = 0x00,
    CRABC_BPF_RET = 0x06,
    CRABC_SECCOMP_SET_MODE_FILTER = 1,
    CRABC_SECCOMP_RET_ALLOW = 0x7fff0000U,
    CRABC_SECCOMP_RET_ERRNO = 0x00050000U,
    CRABC_SECCOMP_ARGUMENT_THREE_LOW = 40,
    CRABC_SECCOMP_ARGUMENT_THREE_HIGH = 44,
    CRABC_SECCOMP_BAD_ARGUMENT_ERRNO = EBADE,
    CRABC_UNKNOWN_SEMCTL_COMMAND = 0x5a,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(struct crabc_bpf_instruction) == 8,
    "Linux classic BPF instruction ABI");
_Static_assert(__builtin_offsetof(struct crabc_bpf_program, instructions) == 8,
    "Linux sock_fprog pointer ABI");

/* The fixed-arity assembly shim enters semctl with only the three C fixed
 * arguments, after overwriting the otherwise-unspecified rcx vararg slot
 * with a nonzero sentinel.  It is linked into the musl reference as well as
 * the freestanding static candidate. */
extern int crabc_x86_64_semctl_poisoned_default_call(
    int semaphore_id, int semaphore_number, int command);

static int semaphore_id = -1;

static long crabc_x86_64_raw_syscall3(long number, long argument_one,
    long argument_two, long argument_three)
{
    long result;

    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three)
        : "rcx", "r11", "memory");
    return result;
}

static long crabc_x86_64_raw_syscall5(long number, long argument_one,
    long argument_two, long argument_three, long argument_four,
    long argument_five)
{
    long result;
    register long linux_argument_four __asm__("r10") = argument_four;
    register long linux_argument_five __asm__("r8") = argument_five;

    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(linux_argument_four),
          "r"(linux_argument_five)
        : "rcx", "r11", "memory");
    return result;
}

static int install_semctl_argument_three_zero_filter(void)
{
    /* Permit all ordinary execution.  For semctl alone, reject a nonzero
     * fourth Linux argument with EBADE rather than allowing the kernel's
     * normal EINVAL for this fixture's intentionally unknown command.  Thus
     * an EINVAL below proves the BPF saw r10=0 after a poisoned C rcx. */
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_semctl, 0, 6),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 3),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_HIGH),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | CRABC_SECCOMP_BAD_ARGUMENT_ERRNO),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (crabc_x86_64_raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0,
            0) != 0)
        return -1;
    if (crabc_x86_64_raw_syscall3(SYS_seccomp,
            CRABC_SECCOMP_SET_MODE_FILTER, 0, (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static void remove_semaphore_if_live(void)
{
    if (semaphore_id >= 0) {
        (void)semctl(semaphore_id, 0, IPC_RMID);
        semaphore_id = -1;
    }
}

static int fail_after_cleanup(int status)
{
    remove_semaphore_if_live();
    return status;
}

int crabc_x86_64_sysv_semaphore_probe(void)
{
    struct sembuf wait_for_zero = { .sem_num = 0, .sem_op = 0, .sem_flg = 0 };
    struct sembuf increment = { .sem_num = 0, .sem_op = 1, .sem_flg = 0 };
    struct sembuf decrement = { .sem_num = 0, .sem_op = -1, .sem_flg = 0 };
    struct sembuf nowait_for_zero = {
        .sem_num = 0,
        .sem_op = 0,
        .sem_flg = IPC_NOWAIT,
    };
    struct timespec zero_timeout = { .tv_sec = 0, .tv_nsec = 0 };
    struct semid_ds status = { 0 };
    union semun argument;
    unsigned short values[1] = { 0 };
    int removed_id;

    /* A creation request with no semaphore slots is rejected directly by the
     * kernel.  This pins raw error translation before we hold a live ID. */
    errno = 0;
    if (semget(IPC_PRIVATE, 0, 0600) != -1 || errno != EINVAL)
        return 10;

    /* Musl rejects a count above the unsigned-short ABI limit before it can
     * reach Linux.  The selected leaf preserves that exact precheck. */
    errno = 0;
    if (semget(IPC_PRIVATE, 65536, 0600) != -1 || errno != EINVAL)
        return 11;

    errno = E2BIG;
    semaphore_id = semget(IPC_PRIVATE, 1, 0600);
    if (semaphore_id < 0 || errno != E2BIG)
        return fail_after_cleanup(12);

    argument.val = 0;
    errno = E2BIG;
    if (semctl(semaphore_id, 0, SETVAL, argument) != 0 || errno != E2BIG)
        return fail_after_cleanup(13);
    errno = E2BIG;
    if (semctl(semaphore_id, 0, GETVAL) != 0 || errno != E2BIG)
        return fail_after_cleanup(14);

    argument.buf = &status;
    errno = E2BIG;
    if (semctl(semaphore_id, 0, IPC_STAT, argument) != 0 ||
        status.sem_nsems != 1 || errno != E2BIG)
        return fail_after_cleanup(15);

    errno = E2BIG;
    if (semop(semaphore_id, &wait_for_zero, 1) != 0 || errno != E2BIG)
        return fail_after_cleanup(16);
    errno = E2BIG;
    if (semop(semaphore_id, &increment, 1) != 0 || errno != E2BIG)
        return fail_after_cleanup(17);
    errno = E2BIG;
    if (semctl(semaphore_id, 0, GETVAL) != 1 || errno != E2BIG)
        return fail_after_cleanup(18);
    errno = E2BIG;
    if (semop(semaphore_id, &decrement, 1) != 0 || errno != E2BIG)
        return fail_after_cleanup(19);

    values[0] = 1;
    argument.array = values;
    errno = E2BIG;
    if (semctl(semaphore_id, 0, SETALL, argument) != 0 || errno != E2BIG)
        return fail_after_cleanup(20);
    values[0] = 0xa5a5;
    errno = E2BIG;
    if (semctl(semaphore_id, 0, GETALL, argument) != 0 || values[0] != 1 ||
        errno != E2BIG)
        return fail_after_cleanup(21);

    errno = 0;
    if (semop(semaphore_id, &nowait_for_zero, 1) != -1 || errno != EAGAIN)
        return fail_after_cleanup(22);

    /* A relative zero timeout makes the blocked operation deterministic: it
     * reaches the distinct semtimedop ABI but cannot leave a waiter behind. */
    errno = 0;
    if (semtimedop(semaphore_id, &wait_for_zero, 1, &zero_timeout) != -1 ||
        errno != EAGAIN || zero_timeout.tv_sec != 0 || zero_timeout.tv_nsec != 0)
        return fail_after_cleanup(23);

    argument.val = 0;
    errno = E2BIG;
    if (semctl(semaphore_id, 0, SETVAL, argument) != 0 || errno != E2BIG)
        return fail_after_cleanup(24);
    errno = E2BIG;
    if (semtimedop(semaphore_id, &wait_for_zero, 1, &zero_timeout) != 0 ||
        errno != E2BIG || zero_timeout.tv_sec != 0 || zero_timeout.tv_nsec != 0)
        return fail_after_cleanup(25);

    /* Explicitly remove the set and then exercise the stale ID.  Clear the
     * cleanup state first so every failure path remains idempotent. */
    removed_id = semaphore_id;
    errno = E2BIG;
    if (semctl(removed_id, 0, IPC_RMID) != 0 || errno != E2BIG)
        return fail_after_cleanup(26);
    semaphore_id = -1;
    errno = 0;
    if (semctl(removed_id, 0, GETVAL) != -1 || errno != EINVAL)
        return 27;

    /* This final call has no fourth C argument.  The assembly shim poisons
     * its otherwise-unspecified rcx slot, then the test-only BPF filter
     * allows the unknown command only when the actual fourth Linux syscall
     * word (r10) is fully zero.  A broken default path yields EBADE from the
     * filter; the allowed kernel path yields its normal EINVAL. */
    if (install_semctl_argument_three_zero_filter() != 0)
        return 28;
    errno = 0;
    if (crabc_x86_64_semctl_poisoned_default_call(removed_id, 0,
            CRABC_UNKNOWN_SEMCTL_COMMAND) != -1 || errno != EINVAL)
        return 29;
    return 0;
}

#ifndef CRABC_SYSV_SEMAPHORE_FREESTANDING
int main(void)
{
    return crabc_x86_64_sysv_semaphore_probe();
}
#endif
