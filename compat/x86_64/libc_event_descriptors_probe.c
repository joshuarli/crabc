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

int crabc_x86_64_event_descriptors_probe(void)
{
    int status = check_eventfd();

    if (status != 0) return status;
    status = check_epoll();
    if (status != 0) return 100 + status;
    status = check_inotify();
    if (status != 0) return 200 + status;
    return 0;
}

#ifndef CRABC_EVENT_DESCRIPTORS_FREESTANDING
int main(void)
{
    return crabc_x86_64_event_descriptors_probe();
}
#endif
