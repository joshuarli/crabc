/*
 * Pinned-musl/raw Linux/x86-64 POSIX named-message-queue reference.
 *
 * The musl calls are a C/POSIX oracle for the private Rust message-queue
 * facade. The raw calls independently pin Linux's fixed-arity mq syscall
 * ABI: unlike the POSIX C spelling, their names omit the leading slash.
 * This fixture selects neither crabc's C ABI nor POSIX shared memory, SysV
 * IPC, semaphores, AIO, notification, errno/TLS, or public x86 support.
 */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 &&
                   sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
               "x86 LP64 scalar widths");
_Static_assert(sizeof(mqd_t) == sizeof(int), "Linux mqd_t is an int descriptor");
_Static_assert(sizeof(struct mq_attr) == 64 && _Alignof(struct mq_attr) == 8,
               "x86 mq_attr layout");
_Static_assert(offsetof(struct mq_attr, mq_flags) == 0 &&
                   offsetof(struct mq_attr, mq_maxmsg) == 8 &&
                   offsetof(struct mq_attr, mq_msgsize) == 16 &&
                   offsetof(struct mq_attr, mq_curmsgs) == 24 &&
                   offsetof(struct mq_attr, __unused) == 32,
               "x86 mq_attr field offsets");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8 &&
                   offsetof(struct timespec, tv_sec) == 0 &&
                   offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec layout");
_Static_assert(SYS_close == 3 && SYS_fcntl == 72, "x86 descriptor syscall numbers");
_Static_assert(SYS_mq_open == 240, "x86 mq_open syscall number");
_Static_assert(SYS_mq_unlink == 241, "x86 mq_unlink syscall number");
_Static_assert(SYS_mq_timedsend == 242, "x86 mq_timedsend syscall number");
_Static_assert(SYS_mq_timedreceive == 243,
               "x86 mq_timedreceive syscall number");
_Static_assert(SYS_mq_getsetattr == 245,
               "x86 mq_getsetattr syscall number");
_Static_assert(O_RDWR == 0x00000002 && O_CREAT == 0x00000040 &&
                   O_EXCL == 0x00000080 && O_NONBLOCK == 0x00000800 &&
                   O_CLOEXEC == 0x00080000 && FD_CLOEXEC == 1,
               "x86 message-queue open and descriptor flags");
_Static_assert(MQ_PRIO_MAX == 32768, "POSIX message-priority ceiling");

enum {
    QUEUE_MODE = 0600,
    QUEUE_MAX_MESSAGES = 2,
    QUEUE_MESSAGE_SIZE = 64,
    QUEUE_FLAGS = O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_CLOEXEC,
};

enum call_kind {
    MUSL_CALL,
    RAW_CALL,
};

struct call_result {
    long value;
    int error;
};

static struct call_result result_from(long value)
{
    struct call_result result = {value, errno};
    return result;
}

static struct call_result queue_create(enum call_kind kind, const char *name,
                                       const struct mq_attr *attributes)
{
    errno = 0;
    if (kind == MUSL_CALL)
        return result_from(mq_open(name, QUEUE_FLAGS, (mode_t)QUEUE_MODE,
                                   attributes));
    return result_from(syscall(SYS_mq_open, name, QUEUE_FLAGS,
                               (mode_t)QUEUE_MODE, attributes));
}

static struct call_result queue_open(enum call_kind kind, const char *name,
                                     int flags)
{
    errno = 0;
    if (kind == MUSL_CALL)
        return result_from(mq_open(name, flags));
    return result_from(syscall(SYS_mq_open, name, flags, 0, NULL));
}

static struct call_result queue_unlink(enum call_kind kind, const char *name)
{
    errno = 0;
    if (kind == MUSL_CALL) return result_from(mq_unlink(name));
    return result_from(syscall(SYS_mq_unlink, name));
}

static struct call_result queue_close(enum call_kind kind, int descriptor)
{
    errno = 0;
    if (kind == MUSL_CALL) return result_from(mq_close(descriptor));
    return result_from(syscall(SYS_close, descriptor));
}

static struct call_result queue_getattr(enum call_kind kind, int descriptor,
                                        struct mq_attr *attributes)
{
    errno = 0;
    if (kind == MUSL_CALL) return result_from(mq_getattr(descriptor, attributes));
    return result_from(
        syscall(SYS_mq_getsetattr, descriptor, NULL, attributes));
}

static struct call_result queue_setattr(enum call_kind kind, int descriptor,
                                        const struct mq_attr *new_attributes,
                                        struct mq_attr *old_attributes)
{
    errno = 0;
    if (kind == MUSL_CALL)
        return result_from(mq_setattr(descriptor, new_attributes, old_attributes));
    return result_from(syscall(SYS_mq_getsetattr, descriptor, new_attributes,
                               old_attributes));
}

static struct call_result queue_send(enum call_kind kind, int descriptor,
                                     const void *message, size_t length,
                                     unsigned priority,
                                     const struct timespec *deadline)
{
    errno = 0;
    if (deadline == NULL) {
        if (kind == MUSL_CALL)
            return result_from(mq_send(descriptor, message, length, priority));
        return result_from(syscall(SYS_mq_timedsend, descriptor, message, length,
                                   priority, NULL));
    }
    if (kind == MUSL_CALL)
        return result_from(
            mq_timedsend(descriptor, message, length, priority, deadline));
    return result_from(syscall(SYS_mq_timedsend, descriptor, message, length,
                               priority, deadline));
}

static struct call_result queue_receive(enum call_kind kind, int descriptor,
                                        void *message, size_t length,
                                        unsigned *priority,
                                        const struct timespec *deadline)
{
    errno = 0;
    if (deadline == NULL) {
        if (kind == MUSL_CALL)
            return result_from(mq_receive(descriptor, message, length, priority));
        return result_from(syscall(SYS_mq_timedreceive, descriptor, message,
                                   length, priority, NULL));
    }
    if (kind == MUSL_CALL)
        return result_from(
            mq_timedreceive(descriptor, message, length, priority, deadline));
    return result_from(syscall(SYS_mq_timedreceive, descriptor, message, length,
                               priority, deadline));
}

static int expected_error(struct call_result result, int error)
{
    return result.value == -1 && result.error == error;
}

static int is_mqueue_unavailable(int error)
{
    return error == ENOENT || error == ENODEV || error == ENOSYS ||
           error == EACCES || error == EPERM;
}

static int has_cloexec(enum call_kind kind, int descriptor)
{
    long flags;

    errno = 0;
    flags = kind == MUSL_CALL ? fcntl(descriptor, F_GETFD)
                              : syscall(SYS_fcntl, descriptor, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

static int expected_attributes(enum call_kind kind, int descriptor,
                               long expected_flags, long expected_current)
{
    struct mq_attr attributes;
    struct call_result result = queue_getattr(kind, descriptor, &attributes);

    return result.value == 0 && attributes.mq_flags == expected_flags &&
           attributes.mq_maxmsg == QUEUE_MAX_MESSAGES &&
           attributes.mq_msgsize == QUEUE_MESSAGE_SIZE &&
           attributes.mq_curmsgs == expected_current;
}

static int set_nonblocking(enum call_kind kind, int descriptor, int enabled,
                           long expected_old_flags)
{
    struct mq_attr new_attributes;
    struct mq_attr old_attributes;
    struct call_result result;

    memset(&new_attributes, 0, sizeof(new_attributes));
    memset(&old_attributes, 0, sizeof(old_attributes));
    new_attributes.mq_flags = enabled ? O_NONBLOCK : 0;
    result = queue_setattr(kind, descriptor, &new_attributes, &old_attributes);
    return result.value == 0 && old_attributes.mq_flags == expected_old_flags;
}

static int received_message(enum call_kind kind, int descriptor,
                            const char *expected, size_t expected_length,
                            unsigned expected_priority)
{
    char received[QUEUE_MESSAGE_SIZE];
    unsigned priority = 0;
    struct call_result result;

    memset(received, 0xa5, sizeof(received));
    result = queue_receive(kind, descriptor, received, sizeof(received),
                           &priority, NULL);
    return result.value == (long)expected_length && priority == expected_priority &&
           memcmp(received, expected, expected_length) == 0 &&
           received[expected_length] == (char)0xa5;
}

/*
 * Exercise one creation spelling and then open the same queue through the
 * other spelling. This proves that POSIX `/name` is translated only at the C
 * boundary, while the raw syscall consumes `name` directly.
 */
static int exercise_queue(enum call_kind owner, const char *owner_name,
                          enum call_kind peer, const char *peer_name)
{
    static const char low[] = "low";
    static const char high[] = "high";
    static const char first[] = "first";
    static const char second[] = "second";
    static const char retained[] = "retained";
    static const struct timespec expired = {0, 0};
    struct mq_attr creation_attributes;
    struct call_result result;
    char empty_message[QUEUE_MESSAGE_SIZE];
    unsigned empty_priority = 0;
    int owner_fd = -1;
    int peer_fd = -1;
    int status = 0;

    memset(&creation_attributes, 0, sizeof(creation_attributes));
    creation_attributes.mq_maxmsg = QUEUE_MAX_MESSAGES;
    creation_attributes.mq_msgsize = QUEUE_MESSAGE_SIZE;
    result = queue_create(owner, owner_name, &creation_attributes);
    if (result.value < 0) {
        if (is_mqueue_unavailable(result.error)) {
            fprintf(stderr,
                    "mqueuefs unavailable: mq_open creation failed (errno=%d)\n",
                    result.error);
            return 77;
        }
        return 1;
    }
    owner_fd = (int)result.value;
    if (!has_cloexec(owner, owner_fd) ||
        !expected_attributes(owner, owner_fd, O_NONBLOCK, 0)) {
        status = 2;
        goto cleanup;
    }

    if (!set_nonblocking(owner, owner_fd, 0, O_NONBLOCK) ||
        !expected_attributes(owner, owner_fd, 0, 0) ||
        !set_nonblocking(owner, owner_fd, 1, 0) ||
        !expected_attributes(owner, owner_fd, O_NONBLOCK, 0)) {
        status = 3;
        goto cleanup;
    }

    result = queue_send(owner, owner_fd, low, sizeof(low) - 1, 1, NULL);
    if (result.value != 0) {
        status = 4;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, high, sizeof(high) - 1, 9, NULL);
    if (result.value != 0 || !expected_attributes(owner, owner_fd, O_NONBLOCK, 2) ||
        !received_message(owner, owner_fd, high, sizeof(high) - 1, 9) ||
        !received_message(owner, owner_fd, low, sizeof(low) - 1, 1) ||
        !expected_attributes(owner, owner_fd, O_NONBLOCK, 0)) {
        status = 5;
        goto cleanup;
    }

    result = queue_receive(owner, owner_fd, empty_message, sizeof(empty_message),
                           &empty_priority, NULL);
    if (!expected_error(result, EAGAIN)) {
        status = 6;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, low, sizeof(low) - 1, MQ_PRIO_MAX, NULL);
    if (!expected_error(result, EINVAL)) {
        status = 7;
        goto cleanup;
    }

    result = queue_send(owner, owner_fd, first, sizeof(first) - 1, 1, NULL);
    if (result.value != 0) {
        status = 8;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, second, sizeof(second) - 1, 2, NULL);
    if (result.value != 0) {
        status = 9;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, high, sizeof(high) - 1, 3, NULL);
    if (!expected_error(result, EAGAIN) ||
        !received_message(owner, owner_fd, second, sizeof(second) - 1, 2) ||
        !received_message(owner, owner_fd, first, sizeof(first) - 1, 1)) {
        status = 10;
        goto cleanup;
    }

    if (!set_nonblocking(owner, owner_fd, 0, O_NONBLOCK)) {
        status = 11;
        goto cleanup;
    }
    result = queue_receive(owner, owner_fd, empty_message, sizeof(empty_message),
                           &empty_priority, &expired);
    if (!expected_error(result, ETIMEDOUT)) {
        status = 12;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, first, sizeof(first) - 1, 1, NULL);
    if (result.value != 0) {
        status = 13;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, second, sizeof(second) - 1, 2, NULL);
    if (result.value != 0) {
        status = 14;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, high, sizeof(high) - 1, 3, &expired);
    if (!expected_error(result, ETIMEDOUT) ||
        !received_message(owner, owner_fd, second, sizeof(second) - 1, 2) ||
        !received_message(owner, owner_fd, first, sizeof(first) - 1, 1)) {
        status = 15;
        goto cleanup;
    }
    if (!set_nonblocking(owner, owner_fd, 1, 0)) {
        status = 16;
        goto cleanup;
    }

    result = queue_open(peer, peer_name, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (result.value < 0 || !has_cloexec(peer, (int)result.value)) {
        status = 17;
        goto cleanup;
    }
    peer_fd = (int)result.value;
    result = queue_unlink(owner, owner_name);
    if (result.value != 0) {
        status = 18;
        goto cleanup;
    }
    result = queue_open(owner, owner_name, O_RDWR | O_NONBLOCK);
    if (!expected_error(result, ENOENT)) {
        status = 19;
        goto cleanup;
    }
    result = queue_open(peer, peer_name, O_RDWR | O_NONBLOCK);
    if (!expected_error(result, ENOENT)) {
        status = 20;
        goto cleanup;
    }
    result = queue_send(owner, owner_fd, retained, sizeof(retained) - 1, 4,
                        NULL);
    if (result.value != 0 ||
        !received_message(peer, peer_fd, retained, sizeof(retained) - 1, 4)) {
        status = 21;
        goto cleanup;
    }

    result = queue_send(owner, -1, low, sizeof(low) - 1, 1, NULL);
    if (!expected_error(result, EBADF)) {
        status = 22;
        goto cleanup;
    }
    result = queue_receive(peer, -1, empty_message, sizeof(empty_message),
                           &empty_priority, NULL);
    if (!expected_error(result, EBADF)) {
        status = 23;
        goto cleanup;
    }
    result = queue_getattr(owner, -1, &(struct mq_attr){0});
    if (!expected_error(result, EBADF)) {
        status = 24;
        goto cleanup;
    }
    result = queue_close(peer, -1);
    if (!expected_error(result, EBADF)) {
        status = 25;
        goto cleanup;
    }

cleanup:
    if (peer_fd >= 0 && queue_close(peer, peer_fd).value != 0 && status == 0)
        status = 26;
    if (owner_fd >= 0 && queue_close(owner, owner_fd).value != 0 && status == 0)
        status = 27;
    /* Ignore ENOENT: successful unlink-after-open already removed the name. */
    (void)queue_unlink(owner, owner_name);
    return status;
}

static int build_names(char *posix_name, size_t posix_capacity,
                       char *kernel_name, size_t kernel_capacity,
                       const char *lane)
{
    int length = snprintf(posix_name, posix_capacity, "/crabc-x86-mq-%ld-%s",
                          (long)getpid(), lane);

    if (length < 2 || (size_t)length >= posix_capacity ||
        (size_t)length >= kernel_capacity) {
        return 0;
    }
    memcpy(kernel_name, posix_name + 1, (size_t)length);
    kernel_name[length - 1] = '\0';
    return 1;
}

int main(void)
{
    char musl_posix_name[96];
    char musl_kernel_name[96];
    char raw_posix_name[96];
    char raw_kernel_name[96];
    struct call_result result;
    int status;

    if (!build_names(musl_posix_name, sizeof(musl_posix_name),
                     musl_kernel_name, sizeof(musl_kernel_name), "musl") ||
        !build_names(raw_posix_name, sizeof(raw_posix_name), raw_kernel_name,
                     sizeof(raw_kernel_name), "raw")) {
        return 2;
    }

    /* The raw syscall rejects the public POSIX `/name` spelling. */
    result = queue_open(RAW_CALL, raw_posix_name, O_RDONLY | O_NONBLOCK);
    if (!expected_error(result, EACCES)) {
        fprintf(stderr,
                "raw leading-slash name did not report EACCES: value=%ld errno=%d\n",
                result.value, result.error);
        return 3;
    }

    /* Clear stale names from an interrupted previous evidence run. */
    (void)queue_unlink(MUSL_CALL, musl_posix_name);
    (void)queue_unlink(RAW_CALL, raw_kernel_name);

    status = exercise_queue(MUSL_CALL, musl_posix_name, RAW_CALL,
                            musl_kernel_name);
    if (status == 77) return 77;
    if (status != 0) return 10 + status;

    status = exercise_queue(RAW_CALL, raw_kernel_name, MUSL_CALL,
                            raw_posix_name);
    if (status == 77) return 77;
    if (status != 0) return 50 + status;

    printf("syscalls=close:3,fcntl:72,mq_open:240,mq_unlink:241,mq_timedsend:242,mq_timedreceive:243,mq_getsetattr:245 abi=mqd_t:i32:mq_attr64@8:timespec16@8 names=posix-leading-slash:raw-without-slash:raw-public-EACCES attrs=maxmsg2:msgsize64:nonblock:cloexec priority=order:range full-empty=EAGAIN deadline=absolute-realtime-ETIMEDOUT lifetime=unlink-after-open direct-errors=EINVAL:ENOENT:EBADF c-api-selection=excluded\n");
    return 0;
}
