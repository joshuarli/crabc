/* Native Linux/x86-64 static event-descriptor C ABI fixture.
 *
 * One project-header C body executes first through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive. It specifies a bounded
 * epoll/eventfd/inotify lifecycle and the x86 syscall argument paths. It is
 * not a general watcher policy, fanotify, timerfd, cancellation, C runtime,
 * loader, sysroot, or public x86 support.
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
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

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
    CRABC_SECCOMP_BAD_ARGUMENT_ERRNO = EBADE,
    CRABC_SECCOMP_ARGUMENT_FOUR_LOW = 48,
    CRABC_SECCOMP_ARGUMENT_FOUR_HIGH = 52,
    CRABC_SECCOMP_ARGUMENT_FIVE_LOW = 56,
    CRABC_SECCOMP_ARGUMENT_FIVE_HIGH = 60,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(eventfd_t) == 8 && _Alignof(eventfd_t) == 8,
    "x86 eventfd_t ABI");
_Static_assert(sizeof(struct epoll_event) == 12 &&
    _Alignof(struct epoll_event) == 1 &&
    offsetof(struct epoll_event, events) == 0 &&
    offsetof(struct epoll_event, data) == 4,
    "x86 packed epoll_event ABI");
_Static_assert(sizeof(struct inotify_event) == 16 &&
    _Alignof(struct inotify_event) == 4 &&
    offsetof(struct inotify_event, wd) == 0 &&
    offsetof(struct inotify_event, mask) == 4 &&
    offsetof(struct inotify_event, cookie) == 8 &&
    offsetof(struct inotify_event, len) == 12 &&
    offsetof(struct inotify_event, name) == 16,
    "x86 inotify event prefix ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_epoll_ctl == 233 &&
    SYS_inotify_add_watch == 254 && SYS_inotify_rm_watch == 255 &&
    SYS_epoll_pwait == 281 && SYS_eventfd2 == 290 &&
    SYS_epoll_create1 == 291 && SYS_inotify_init1 == 294,
    "x86 selected event-descriptor syscall numbers");
_Static_assert(EFD_SEMAPHORE == 1 && EFD_CLOEXEC == O_CLOEXEC &&
    EFD_NONBLOCK == O_NONBLOCK && EPOLL_CLOEXEC == O_CLOEXEC &&
    IN_CLOEXEC == O_CLOEXEC && IN_NONBLOCK == O_NONBLOCK,
    "selected event-descriptor creation flags");
_Static_assert(CRABC_TYPE_IS(__typeof__(&epoll_create), int (*)(int)) &&
    CRABC_TYPE_IS(__typeof__(&epoll_create1), int (*)(int)) &&
    CRABC_TYPE_IS(__typeof__(&epoll_ctl),
        int (*)(int, int, int, struct epoll_event *)) &&
    CRABC_TYPE_IS(__typeof__(&epoll_wait),
        int (*)(int, struct epoll_event *, int, int)) &&
    CRABC_TYPE_IS(__typeof__(&epoll_pwait),
        int (*)(int, struct epoll_event *, int, int, const sigset_t *)) &&
    CRABC_TYPE_IS(__typeof__(&eventfd), int (*)(unsigned int, int)) &&
    CRABC_TYPE_IS(__typeof__(&eventfd_read), int (*)(int, eventfd_t *)) &&
    CRABC_TYPE_IS(__typeof__(&eventfd_write), int (*)(int, eventfd_t)) &&
    CRABC_TYPE_IS(__typeof__(&inotify_init), int (*)(void)) &&
    CRABC_TYPE_IS(__typeof__(&inotify_init1), int (*)(int)) &&
    CRABC_TYPE_IS(__typeof__(&inotify_add_watch),
        int (*)(int, const char *, uint32_t)) &&
    CRABC_TYPE_IS(__typeof__(&inotify_rm_watch), int (*)(int, int)),
    "selected event-descriptor declarations");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static long raw_syscall3(long number, long argument_one, long argument_two,
    long argument_three)
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

static long raw_syscall5(long number, long argument_one, long argument_two,
    long argument_three, long argument_four, long argument_five)
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

/* Keep this test-only BPF contract local. `seccomp_data` puts syscall number
 * at byte zero and argument N at byte 16 + 8*N. The filter below accepts
 * epoll_pwait only when its fifth argument—the signal-mask pointer sent in
 * x86 r8—matches the caller's mask and its sixth argument—the kernel sigset
 * size sent in x86 r9—is exactly eight. A wrong public 128-byte or
 * uninitialized word yields EBADE before Linux consumes the event array. */
static int install_epoll_pwait_signal_argument_filter(const void *signal_mask)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_epoll_pwait, 0, 10),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FOUR_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 7),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FOUR_HIGH),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 5),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FIVE_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 8, 0, 3),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FIVE_HIGH),
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

    filter[3].immediate = (uint32_t)(uintptr_t)signal_mask;
    filter[5].immediate = (uint32_t)((uintptr_t)signal_mask >> 32);

    if (raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
        (long)(uintptr_t)&program) == 0 ? 0 : -1;
}

static int has_descriptor_flags(int fd, int descriptor_flags, int status_flags)
{
    int observed_descriptor_flags = fcntl(fd, F_GETFD);
    int observed_status_flags = fcntl(fd, F_GETFL);

    return observed_descriptor_flags >= 0 && observed_status_flags >= 0 &&
        (observed_descriptor_flags & descriptor_flags) == descriptor_flags &&
        (observed_status_flags & status_flags) == status_flags;
}

static int check_eventfd(void)
{
    eventfd_t value = 0;
    int ordinary = -1;
    int semaphore = -1;
    int status = 0;

    ordinary = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ordinary < 0 || !has_descriptor_flags(ordinary, FD_CLOEXEC, O_NONBLOCK)) {
        status = 1;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(eventfd_read(ordinary, &value), EAGAIN)) {
        status = 2;
        goto cleanup;
    }
    errno = E2BIG;
    if (eventfd_write(ordinary, UINT64_C(7)) != 0 || errno != E2BIG ||
        eventfd_read(ordinary, &value) != 0 || value != UINT64_C(7) ||
        errno != E2BIG) {
        status = 3;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(eventfd_write(ordinary, UINT64_MAX), EINVAL)) {
        status = 4;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(eventfd(0, 2), EINVAL)) {
        status = 5;
        goto cleanup;
    }

    semaphore = eventfd(0, EFD_SEMAPHORE);
    if (semaphore < 0 || eventfd_write(semaphore, UINT64_C(2)) != 0 ||
        eventfd_read(semaphore, &value) != 0 || value != UINT64_C(1) ||
        eventfd_read(semaphore, &value) != 0 || value != UINT64_C(1)) {
        status = 6;
        goto cleanup;
    }

cleanup:
    if (semaphore >= 0 && close(semaphore) != 0 && status == 0) status = 7;
    if (ordinary >= 0 && close(ordinary) != 0 && status == 0) status = 8;
    return status;
}

static int check_epoll(void)
{
    const uint64_t added_token = UINT64_C(0x1122334455667788);
    const uint64_t modified_token = UINT64_C(0x8877665544332211);
    struct epoll_event interest = { 0 };
    struct epoll_event observed = { 0 };
    sigset_t block_usr1 = { 0 };
    sigset_t empty = { 0 };
    sigset_t previous = { 0 };
    sigset_t current = { 0 };
    eventfd_t value = 0;
    int legacy = -1;
    int source = -1;
    int epoll = -1;
    int status = 0;

    errno = 0;
    if (!expect_error(epoll_create(0), EINVAL)) return 1;
    legacy = epoll_create(1);
    if (legacy < 0 || has_descriptor_flags(legacy, FD_CLOEXEC, 0)) {
        status = 2;
        goto cleanup;
    }
    if (close(legacy) != 0) {
        legacy = -1;
        status = 3;
        goto cleanup;
    }
    legacy = -1;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    source = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (epoll < 0 || source < 0 || !has_descriptor_flags(epoll, FD_CLOEXEC, 0)) {
        status = 4;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(epoll_create1(EPOLL_NONBLOCK), EINVAL)) {
        status = 5;
        goto cleanup;
    }
    interest.events = EPOLLIN;
    interest.data.u64 = added_token;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, source, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0 ||
        eventfd_write(source, UINT64_C(4)) != 0) {
        status = 6;
        goto cleanup;
    }
    observed.events = 0;
    observed.data.u64 = 0;
    if (epoll_wait(epoll, &observed, 1, 0) != 1 ||
        (observed.events & EPOLLIN) == 0 || observed.data.u64 != added_token ||
        eventfd_read(source, &value) != 0 || value != UINT64_C(4)) {
        status = 7;
        goto cleanup;
    }
    interest.data.u64 = modified_token;
    if (epoll_ctl(epoll, EPOLL_CTL_MOD, source, &interest) != 0 ||
        eventfd_write(source, UINT64_C(1)) != 0) {
        status = 8;
        goto cleanup;
    }
    observed.events = 0;
    observed.data.u64 = 0;
    if (epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.data.u64 != modified_token || eventfd_read(source, &value) != 0 ||
        value != UINT64_C(1)) {
        status = 9;
        goto cleanup;
    }
    if (epoll_ctl(epoll, EPOLL_CTL_DEL, source, 0) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 10;
        goto cleanup;
    }

    if (sigemptyset(&block_usr1) != 0 || sigaddset(&block_usr1, SIGUSR1) != 0 ||
        sigemptyset(&empty) != 0 ||
        sigprocmask(SIG_BLOCK, &block_usr1, &previous) != 0 ||
        install_epoll_pwait_signal_argument_filter(&empty) != 0) {
        status = 11;
        goto restore_mask;
    }
    errno = E2BIG;
    if (epoll_pwait(epoll, &observed, 1, 0, &empty) != 0 || errno != E2BIG ||
        sigprocmask(SIG_SETMASK, 0, &current) != 0 ||
        sigismember(&current, SIGUSR1) != 1) {
        status = 12;
    }

restore_mask:
    if (sigprocmask(SIG_SETMASK, &previous, 0) != 0 && status == 0) status = 13;
    if (status != 0) goto cleanup;

    errno = 0;
    if (!expect_error(epoll_ctl(epoll, 99, source, &interest), EINVAL) ||
        !expect_error(epoll_pwait(epoll, &observed, 0, 0, &empty), EINVAL)) {
        status = 14;
    }

cleanup:
    if (source >= 0 && close(source) != 0 && status == 0) status = 15;
    if (epoll >= 0 && close(epoll) != 0 && status == 0) status = 16;
    return status;
}

static int check_eventfd_epoll_readiness(void)
{
    const uint64_t counter_token = UINT64_C(0x1020304050607080);
    const uint64_t semaphore_token = UINT64_C(0x8070605040302010);
    struct epoll_event interest = { 0 };
    struct epoll_event observed = { 0 };
    eventfd_t value = 0;
    int epoll = -1;
    int counter = -1;
    int semaphore = -1;
    int status = 0;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    counter = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (epoll < 0 || counter < 0) {
        status = 1;
        goto cleanup;
    }
    interest.events = EPOLLIN | EPOLLOUT;
    interest.data.u64 = counter_token;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, counter, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLOUT || observed.data.u64 != counter_token) {
        status = 2;
        goto cleanup;
    }

    /* The largest writable counter is readable but cannot accept another
     * increment; draining it reverses the two readiness bits. */
    if (eventfd_write(counter, UINT64_MAX - 1) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != counter_token) {
        status = 3;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(eventfd_write(counter, 1), EAGAIN) ||
        eventfd_read(counter, &value) != 0 || value != UINT64_MAX - 1 ||
        errno != EAGAIN ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLOUT || observed.data.u64 != counter_token) {
        status = 4;
        goto cleanup;
    }
    if (epoll_ctl(epoll, EPOLL_CTL_DEL, counter, 0) != 0) {
        status = 5;
        goto cleanup;
    }

    semaphore = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    if (semaphore < 0) {
        status = 6;
        goto cleanup;
    }
    interest.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    interest.data.u64 = semaphore_token;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, semaphore, &interest) != 0 ||
        eventfd_write(semaphore, 2) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != semaphore_token ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 7;
        goto cleanup;
    }

    /* One semaphore read leaves the counter readable. Rearming a one-shot
     * edge interest must report that existing readiness once more. */
    if (eventfd_read(semaphore, &value) != 0 || value != 1 ||
        epoll_ctl(epoll, EPOLL_CTL_MOD, semaphore, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != semaphore_token ||
        eventfd_read(semaphore, &value) != 0 || value != 1 ||
        epoll_ctl(epoll, EPOLL_CTL_MOD, semaphore, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0 ||
        eventfd_write(semaphore, 1) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != semaphore_token) {
        status = 8;
    }

cleanup:
    if (semaphore >= 0 && close(semaphore) != 0 && status == 0) status = 9;
    if (counter >= 0 && close(counter) != 0 && status == 0) status = 10;
    if (epoll >= 0 && close(epoll) != 0 && status == 0) status = 11;
    return status;
}

static int check_epoll_descriptor_reuse(void)
{
    struct descriptor_reuse_receipt {
        uint64_t reused_number;
        uint64_t stale_modify_errno;
        uint64_t old_events;
        uint64_t old_token;
        uint64_t replacement_events;
        uint64_t replacement_token;
        uint64_t rearmed_events;
        uint64_t rearmed_token;
    };
    _Static_assert(sizeof(struct descriptor_reuse_receipt) == 64,
        "descriptor reuse observation record has eight 64-bit fields");
    const uint64_t old_token = UINT64_C(0x13579bdf2468ace0);
    const uint64_t replacement_token = UINT64_C(0x02468ace13579bdf);
    const uint64_t rearmed_token = UINT64_C(0xfedcba9876543210);
    struct descriptor_reuse_receipt receipt = { 0 };
    struct epoll_event interest = { 0 };
    struct epoll_event observed = { 0 };
    eventfd_t value = 0;
    int epoll = -1;
    int source = -1;
    int duplicate = -1;
    int replacement = -1;
    int source_number = -1;
    int status = 0;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    source = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (epoll < 0 || source < 0) {
        status = 1;
        goto cleanup;
    }
    interest.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    interest.data.u64 = old_token;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, source, &interest) != 0 ||
        (duplicate = dup(source)) < 0) {
        status = 2;
        goto cleanup;
    }
    source_number = source;
    if (close(source) != 0) {
        status = 3;
        goto cleanup;
    }
    source = -1;
    replacement = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (replacement < 0 || replacement != source_number) {
        status = 4;
        goto cleanup;
    }
    receipt.reused_number = 1;

    /* The reused number names a different open file description. The old
     * interest survives through duplicate, but cannot modify the new one. */
    errno = 0;
    if (!expect_error(epoll_ctl(epoll, EPOLL_CTL_MOD, replacement, &interest),
            ENOENT)) {
        status = 5;
        goto cleanup;
    }
    receipt.stale_modify_errno = (uint64_t)errno;
    if (eventfd_write(duplicate, 1) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != old_token ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 6;
        goto cleanup;
    }
    receipt.old_events = observed.events;
    receipt.old_token = observed.data.u64;

    interest.data.u64 = replacement_token;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, replacement, &interest) != 0 ||
        eventfd_write(replacement, 1) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN ||
        observed.data.u64 != replacement_token ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 7;
        goto cleanup;
    }
    receipt.replacement_events = observed.events;
    receipt.replacement_token = observed.data.u64;

    /* Closing the last old duplicate removes only its registration. Rearming
     * the still-readable replacement must retain its own data and readiness. */
    if (close(duplicate) != 0) {
        status = 8;
        goto cleanup;
    }
    duplicate = -1;
    interest.data.u64 = rearmed_token;
    if (epoll_ctl(epoll, EPOLL_CTL_MOD, replacement, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != rearmed_token ||
        eventfd_read(replacement, &value) != 0 || value != 1 ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 9;
        goto cleanup;
    }
    receipt.rearmed_events = observed.events;
    receipt.rearmed_token = observed.data.u64;
    if (write(STDOUT_FILENO, &receipt, sizeof(receipt)) !=
        (ssize_t)sizeof(receipt)) {
        status = 10;
    }

cleanup:
    if (replacement >= 0 && close(replacement) != 0 && status == 0) status = 11;
    if (duplicate >= 0 && close(duplicate) != 0 && status == 0) status = 12;
    if (source >= 0 && close(source) != 0 && status == 0) status = 13;
    if (epoll >= 0 && close(epoll) != 0 && status == 0) status = 14;
    return status;
}

static int read_created_event(int fd, int watch)
{
    unsigned char bytes[64] = { 0 };
    struct inotify_event event;
    ssize_t length = read(fd, bytes, sizeof(bytes));

    if (length < (ssize_t)sizeof(event)) return 0;
    __builtin_memcpy(&event, bytes, sizeof(event));
    return event.wd == watch && (event.mask & IN_CREATE) != 0 &&
        event.len >= 8 && bytes[sizeof(event)] == 'c' &&
        bytes[sizeof(event) + 1] == 'r' && bytes[sizeof(event) + 2] == 'e' &&
        bytes[sizeof(event) + 3] == 'a' && bytes[sizeof(event) + 4] == 't' &&
        bytes[sizeof(event) + 5] == 'e' && bytes[sizeof(event) + 6] == 'd' &&
        bytes[sizeof(event) + 7] == '\0';
}

static int read_ignored_event(int fd, int watch)
{
    unsigned char bytes[64] = { 0 };
    struct inotify_event event;
    ssize_t length = read(fd, bytes, sizeof(bytes));

    if (length < (ssize_t)sizeof(event)) return 0;
    __builtin_memcpy(&event, bytes, sizeof(event));
    return event.wd == watch && (event.mask & IN_IGNORED) != 0 && event.len == 0;
}

/* A read can contain multiple variable records. Consume each complete record
 * before checking the next name, so the second rename event is not mistaken
 * for padding in the first event's name storage. */
static int consume_named_event(const unsigned char *bytes, ssize_t length,
    size_t *offset, int watch, uint32_t mask, const char *name,
    size_t name_size, uint32_t *cookie)
{
    struct inotify_event event;

    if (*offset > (size_t)length ||
        (size_t)length - *offset < sizeof(event)) return 0;
    __builtin_memcpy(&event, bytes + *offset, sizeof(event));
    if (event.wd != watch || event.mask != mask ||
        (event.len & 3) != 0 || event.len < name_size ||
        event.len > (size_t)length - *offset - sizeof(event) ||
        __builtin_memcmp(bytes + *offset + sizeof(event), name,
            name_size) != 0) return 0;
    *offset += sizeof(event) + event.len;
    if (cookie != 0) *cookie = event.cookie;
    return 1;
}

static int check_inotify(void)
{
    int legacy = -1;
    int descriptor = -1;
    int created = -1;
    int watch = -1;
    int status = 0;

    legacy = inotify_init();
    if (legacy < 0 || close(legacy) != 0) return 1;
    legacy = -1;
    descriptor = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (descriptor < 0 ||
        !has_descriptor_flags(descriptor, FD_CLOEXEC, O_NONBLOCK)) {
        status = 2;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(inotify_init1(1), EINVAL) ||
        !expect_error(inotify_add_watch(descriptor, "missing", IN_CREATE), ENOENT) ||
        !expect_error(inotify_add_watch(-1, ".", IN_CREATE), EBADF)) {
        status = 3;
        goto cleanup;
    }
    watch = inotify_add_watch(descriptor, ".", IN_CREATE);
    if (watch < 0) {
        status = 4;
        goto cleanup;
    }
    created = open("created", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (created < 0 || close(created) != 0) {
        created = -1;
        status = 5;
        goto cleanup;
    }
    created = -1;
    if (!read_created_event(descriptor, watch)) {
        status = 6;
        goto cleanup;
    }
    if (inotify_rm_watch(descriptor, watch) != 0 ||
        !read_ignored_event(descriptor, watch)) {
        status = 7;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(inotify_rm_watch(descriptor, watch), EINVAL) ||
        !expect_error(inotify_rm_watch(-1, 0), EBADF)) {
        status = 8;
    }

cleanup:
    if (created >= 0 && close(created) != 0 && status == 0) status = 9;
    if (descriptor >= 0 && close(descriptor) != 0 && status == 0) status = 10;
    return status;
}

static int check_inotify_epoll_lifecycle(void)
{
    struct inotify_epoll_receipt {
        uint64_t duplicate_errno;
        uint64_t create_ready;
        uint64_t token;
        uint64_t create_mask;
        uint64_t name_capacity;
        uint64_t ignored_ready;
        uint64_t ignored_mask;
        uint64_t removed_errno;
    };
    _Static_assert(sizeof(struct inotify_epoll_receipt) == 64,
        "inotify epoll observation record has eight 64-bit fields");
    const uint64_t token = UINT64_C(0x9a8b7c6d5e4f3021);
    const char name[] = "epoll-created";
    unsigned char bytes[64] = { 0 };
    struct epoll_event interest = { 0 };
    struct epoll_event observed = { 0 };
    struct inotify_event event;
    struct inotify_epoll_receipt receipt = { 0 };
    ssize_t length;
    int epoll = -1;
    int descriptor = -1;
    int created = -1;
    int watch = -1;
    int status = 0;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    descriptor = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (epoll < 0 || descriptor < 0 ||
        !has_descriptor_flags(epoll, FD_CLOEXEC, 0) ||
        !has_descriptor_flags(descriptor, FD_CLOEXEC, O_NONBLOCK)) {
        status = 1;
        goto cleanup;
    }
    watch = inotify_add_watch(descriptor, ".", IN_CREATE);
    interest.events = EPOLLIN | EPOLLONESHOT;
    interest.data.u64 = token;
    if (watch < 0 || epoll_ctl(epoll, EPOLL_CTL_ADD, descriptor, &interest) != 0) {
        status = 2;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(epoll_ctl(epoll, EPOLL_CTL_ADD, descriptor, &interest),
            EEXIST)) {
        status = 3;
        goto cleanup;
    }
    receipt.duplicate_errno = (uint64_t)errno;
    errno = E2BIG;
    if (epoll_wait(epoll, &observed, 1, 0) != 0 || errno != E2BIG) {
        status = 4;
        goto cleanup;
    }
    created = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (created < 0 || close(created) != 0) {
        status = 5;
        goto cleanup;
    }
    created = -1;
    observed.events = 0;
    observed.data.u64 = 0;
    if (epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != token) {
        status = 6;
        goto cleanup;
    }
    receipt.create_ready = observed.events;
    receipt.token = observed.data.u64;
    if (epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 7;
        goto cleanup;
    }
    length = read(descriptor, bytes, sizeof(bytes));
    if (length < (ssize_t)sizeof(event)) {
        status = 8;
        goto cleanup;
    }
    __builtin_memcpy(&event, bytes, sizeof(event));
    if (event.wd != watch || event.mask != IN_CREATE ||
        event.len < sizeof(name) ||
        __builtin_memcmp(bytes + sizeof(event), name, sizeof(name)) != 0 ||
        length != (ssize_t)(sizeof(event) + event.len)) {
        status = 9;
        goto cleanup;
    }
    receipt.create_mask = event.mask;
    receipt.name_capacity = event.len;
    errno = E2BIG;
    if (epoll_ctl(epoll, EPOLL_CTL_MOD, descriptor, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0 || errno != E2BIG) {
        status = 10;
        goto cleanup;
    }
    if (inotify_rm_watch(descriptor, watch) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN || observed.data.u64 != token) {
        status = 11;
        goto cleanup;
    }
    receipt.ignored_ready = observed.events;
    length = read(descriptor, bytes, sizeof(bytes));
    if (length != (ssize_t)sizeof(event)) {
        status = 12;
        goto cleanup;
    }
    __builtin_memcpy(&event, bytes, sizeof(event));
    if (event.wd != watch || event.mask != IN_IGNORED || event.len != 0) {
        status = 13;
        goto cleanup;
    }
    receipt.ignored_mask = event.mask;
    errno = 0;
    if (!expect_error(inotify_rm_watch(descriptor, watch), EINVAL)) {
        status = 14;
        goto cleanup;
    }
    receipt.removed_errno = (uint64_t)errno;
    if (epoll_ctl(epoll, EPOLL_CTL_MOD, descriptor, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0 ||
        !has_descriptor_flags(descriptor, FD_CLOEXEC, O_NONBLOCK)) {
        status = 14;
        goto cleanup;
    }
    if (write(STDOUT_FILENO, &receipt, sizeof(receipt)) !=
        (ssize_t)sizeof(receipt)) {
        status = 15;
    }

cleanup:
    if (created >= 0 && close(created) != 0 && status == 0) status = 16;
    if (descriptor >= 0 && close(descriptor) != 0 && status == 0) status = 17;
    if (epoll >= 0 && close(epoll) != 0 && status == 0) status = 18;
    return status;
}

static int check_inotify_rename_and_readd(void)
{
    struct inotify_rename_receipt {
        uint64_t same_watch;
        uint64_t rename_ready;
        uint64_t from_mask;
        uint64_t to_mask;
        uint64_t matching_cookie;
        uint64_t delete_mask;
        uint64_t ignored_mask;
        uint64_t new_watch;
        uint64_t create_ready;
        uint64_t readd_create_mask;
    } receipt = { 0 };
    const char from[] = "rename-from";
    const char to[] = "rename-to";
    const char readded[] = "readded";
    unsigned char bytes[128] = { 0 };
    struct epoll_event interest = { 0 };
    struct epoll_event observed = { 0 };
    struct inotify_event ignored;
    uint32_t from_cookie = 0;
    uint32_t to_cookie = 0;
    ssize_t length;
    size_t offset;
    int descriptor = -1;
    int epoll = -1;
    int file = -1;
    int watch = -1;
    int new_watch = -1;
    int status = 0;

    file = open(from, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file < 0 || close(file) != 0) return 1;
    file = -1;
    descriptor = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    epoll = epoll_create1(EPOLL_CLOEXEC);
    if (descriptor < 0 || epoll < 0) {
        status = 2;
        goto cleanup;
    }
    watch = inotify_add_watch(descriptor, ".", IN_MOVED_FROM | IN_MOVED_TO);
    if (watch < 0 || inotify_add_watch(descriptor, ".",
            IN_MASK_ADD | IN_DELETE) != watch) {
        status = 3;
        goto cleanup;
    }
    receipt.same_watch = 1;
    interest.events = EPOLLIN;
    interest.data.u64 = UINT64_C(0x4f5e6d7c8b9a1023);
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, descriptor, &interest) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 4;
        goto cleanup;
    }
    if (raw_syscall3(SYS_rename, (long)(uintptr_t)from,
            (long)(uintptr_t)to, 0) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN ||
        observed.data.u64 != interest.data.u64) {
        status = 5;
        goto cleanup;
    }
    receipt.rename_ready = observed.events;
    length = read(descriptor, bytes, sizeof(bytes));
    offset = 0;
    if (length <= 0 ||
        !consume_named_event(bytes, length, &offset, watch, IN_MOVED_FROM,
            from, sizeof(from), &from_cookie) ||
        !consume_named_event(bytes, length, &offset, watch, IN_MOVED_TO,
            to, sizeof(to), &to_cookie) ||
        offset != (size_t)length || from_cookie == 0 ||
        from_cookie != to_cookie ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 6;
        goto cleanup;
    }
    receipt.from_mask = IN_MOVED_FROM;
    receipt.to_mask = IN_MOVED_TO;
    receipt.matching_cookie = 1;
    if (raw_syscall3(SYS_unlink, (long)(uintptr_t)to, 0, 0) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN) {
        status = 7;
        goto cleanup;
    }
    length = read(descriptor, bytes, sizeof(bytes));
    offset = 0;
    if (length <= 0 ||
        !consume_named_event(bytes, length, &offset, watch, IN_DELETE,
            to, sizeof(to), 0) || offset != (size_t)length) {
        status = 8;
        goto cleanup;
    }
    receipt.delete_mask = IN_DELETE;
    if (inotify_rm_watch(descriptor, watch) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN) {
        status = 9;
        goto cleanup;
    }
    length = read(descriptor, bytes, sizeof(bytes));
    if (length != (ssize_t)sizeof(ignored)) {
        status = 10;
        goto cleanup;
    }
    __builtin_memcpy(&ignored, bytes, sizeof(ignored));
    if (ignored.wd != watch || ignored.mask != IN_IGNORED ||
        ignored.cookie != 0 || ignored.len != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 11;
        goto cleanup;
    }
    receipt.ignored_mask = ignored.mask;
    new_watch = inotify_add_watch(descriptor, ".", IN_CREATE);
    if (new_watch < 0 || new_watch == watch ||
        !expect_error(inotify_rm_watch(descriptor, watch), EINVAL)) {
        status = 12;
        goto cleanup;
    }
    receipt.new_watch = 1;
    file = open(readded, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file < 0 || close(file) != 0 ||
        epoll_wait(epoll, &observed, 1, 0) != 1 ||
        observed.events != EPOLLIN) {
        status = 13;
        goto cleanup;
    }
    file = -1;
    receipt.create_ready = observed.events;
    length = read(descriptor, bytes, sizeof(bytes));
    offset = 0;
    if (length <= 0 ||
        !consume_named_event(bytes, length, &offset, new_watch, IN_CREATE,
            readded, sizeof(readded), 0) || offset != (size_t)length ||
        epoll_wait(epoll, &observed, 1, 0) != 0) {
        status = 14;
        goto cleanup;
    }
    receipt.readd_create_mask = IN_CREATE;
    if (write(STDOUT_FILENO, &receipt, sizeof(receipt)) !=
        (ssize_t)sizeof(receipt)) status = 15;

cleanup:
    if (file >= 0 && close(file) != 0 && status == 0) status = 16;
    if (descriptor >= 0 && close(descriptor) != 0 && status == 0) status = 17;
    if (epoll >= 0 && close(epoll) != 0 && status == 0) status = 18;
    return status;
}

int crabc_x86_64_event_descriptors_probe(void)
{
    int status = check_eventfd();

    if (status != 0) return status;
    status = check_eventfd_epoll_readiness();
    if (status != 0) return 300 + status;
    status = check_epoll_descriptor_reuse();
    if (status != 0) return 500 + status;
    status = check_inotify();
    if (status != 0) return 200 + status;
    status = check_inotify_epoll_lifecycle();
    if (status != 0) return 400 + status;
    status = check_inotify_rename_and_readd();
    if (status != 0) return 600 + status;
    /* The epoll argument filter is permanent for this process. */
    status = check_epoll();
    if (status != 0) return 100 + status;
    return 0;
}

#ifndef CRABC_EVENT_DESCRIPTORS_FREESTANDING
int main(void)
{
    return crabc_x86_64_event_descriptors_probe();
}
#endif
