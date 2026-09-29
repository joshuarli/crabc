/* Static crabc-libc x86-64 selected socket-message/options fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * `libc.a`. It extends the already selected socket-transport and vector-I/O
 * records only with socket options, padded send/receive message records,
 * bounded batched message calls, repeated descriptor peeks, the 253-rights
 * limit, close-on-exec, credentials, zero-length records, error precedence,
 * ancillary and payload truncation, and SIOCATMARK. Poisoned public padding
 * proves the musl-shaped adapter rather than a raw Linux msghdr call.
 * Fixture-local raw close/fcntl calls only clean up and inspect received
 * descriptors; they do not select generic descriptor, ioctl,
 * cancellation, allocator, CRT, loader, sysroot, or public x86 support.
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
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

_Static_assert(sizeof(socklen_t) == 4 && _Alignof(socklen_t) == 4 &&
    sizeof(ssize_t) == 8, "x86 socket scalar widths");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 iovec ABI");
_Static_assert(sizeof(struct msghdr) == 56 && _Alignof(struct msghdr) == 8 &&
    offsetof(struct msghdr, msg_name) == 0 &&
    offsetof(struct msghdr, msg_namelen) == 8 &&
    offsetof(struct msghdr, msg_iov) == 16 &&
    offsetof(struct msghdr, msg_iovlen) == 24 &&
    offsetof(struct msghdr, __pad1) == 28 &&
    offsetof(struct msghdr, msg_control) == 32 &&
    offsetof(struct msghdr, msg_controllen) == 40 &&
    offsetof(struct msghdr, __pad2) == 44 &&
    offsetof(struct msghdr, msg_flags) == 48,
    "x86 public msghdr ABI");
_Static_assert(sizeof(struct cmsghdr) == 16 && _Alignof(struct cmsghdr) == 4 &&
    offsetof(struct cmsghdr, cmsg_len) == 0 &&
    offsetof(struct cmsghdr, __pad1) == 4 &&
    offsetof(struct cmsghdr, cmsg_level) == 8 &&
    offsetof(struct cmsghdr, cmsg_type) == 12,
    "x86 public cmsghdr ABI");
_Static_assert(sizeof(struct mmsghdr) == 64 && _Alignof(struct mmsghdr) == 8 &&
    offsetof(struct mmsghdr, msg_hdr) == 0 &&
    offsetof(struct mmsghdr, msg_len) == 56,
    "x86 public mmsghdr ABI");
_Static_assert(CMSG_LEN(sizeof(int)) == 20 && CMSG_SPACE(sizeof(int)) == 24 &&
    CMSG_SPACE(255 * sizeof(int)) == 1040,
    "x86 ancillary alignment bounds");
_Static_assert(SYS_close == 3 && SYS_fcntl == 72 && SYS_ioctl == 16 &&
    SYS_sendmsg == 46 && SYS_recvmsg == 47 && SYS_setsockopt == 54 &&
    SYS_getsockopt == 55 && SYS_recvmmsg == 299 && SYS_sendmmsg == 307,
    "x86 socket-message syscall numbers");
_Static_assert(SOL_SOCKET == 1 && SO_TYPE == 3 && SO_SNDBUF == 7 &&
    SCM_RIGHTS == 1 && SCM_CREDENTIALS == 2 && SO_PASSCRED == 16 &&
    SIOCATMARK == 0x8905,
    "selected socket-message values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setsockopt),
    int (*)(int, int, int, const void *, socklen_t)), "setsockopt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getsockopt),
    int (*)(int, int, int, void *, socklen_t *)), "getsockopt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendmsg),
    ssize_t (*)(int, const struct msghdr *, int)), "sendmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvmsg),
    ssize_t (*)(int, struct msghdr *, int)), "recvmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendmmsg),
    int (*)(int, struct mmsghdr *, unsigned int, unsigned int)),
    "sendmmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvmmsg),
    int (*)(int, struct mmsghdr *, unsigned int, unsigned int,
        struct timespec *)), "recvmmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sockatmark),
    int (*)(int)), "sockatmark declaration");

static long raw1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
    return result;
}

static void raw_close(int descriptor)
{
    if (descriptor >= 0)
        (void)raw1(SYS_close, descriptor);
}

static int raw_getfd(int descriptor)
{
    return (int)raw3(SYS_fcntl, descriptor, F_GETFD, 0);
}

static int open_descriptor_count(void)
{
    int descriptor;
    int count = 0;

    for (descriptor = 0; descriptor < 1024; ++descriptor)
        if (raw_getfd(descriptor) >= 0)
            ++count;
    return count;
}

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = left;
    const unsigned char *right_bytes = right;
    size_t index;

    for (index = 0; index < length; ++index)
        if (left_bytes[index] != right_bytes[index])
            return 0;
    return 1;
}

static void copy_bytes(void *destination, const void *source, size_t length)
{
    unsigned char *destination_bytes = destination;
    const unsigned char *source_bytes = source;
    size_t index;

    for (index = 0; index < length; ++index)
        destination_bytes[index] = source_bytes[index];
}

static int check_socket_options(void)
{
    int pair[2] = { -1, -1 };
    int send_buffer = 4096;
    int type = 0;
    socklen_t type_length = sizeof(type);
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0 || pair[0] < 0 ||
        pair[1] < 0) {
        status = 1;
        goto finish;
    }
    errno = EINTR;
    if (setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &send_buffer,
            sizeof(send_buffer)) != 0 || errno != EINTR) {
        status = 2;
        goto finish;
    }
    errno = ERANGE;
    if (getsockopt(pair[0], SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
        type != SOCK_DGRAM || type_length != sizeof(type) || errno != ERANGE) {
        status = 3;
        goto finish;
    }
    errno = 0;
    if (setsockopt(-1, SOL_SOCKET, SO_SNDBUF, &send_buffer,
            sizeof(send_buffer)) != -1 || errno != EBADF) {
        status = 4;
        goto finish;
    }
    errno = 0;
    if (getsockopt(-1, SOL_SOCKET, SO_TYPE, &type, &type_length) != -1 ||
        errno != EBADF) {
        status = 5;
    }

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_sendmsg_recvmsg(void)
{
    static const char first[] = "hello";
    static const char second[] = "-world";
    static const char expected[] = "hello-world";
    char received_first[sizeof(first) - 1] = { 0 };
    char received_second[sizeof(second) - 1] = { 0 };
    unsigned char send_control[CMSG_SPACE(sizeof(int))] = { 0 };
    unsigned char receive_control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct iovec send_iov[2] = {
        { (void *)first, sizeof(first) - 1 },
        { (void *)second, sizeof(second) - 1 },
    };
    struct iovec receive_iov[2] = {
        { received_first, sizeof(received_first) },
        { received_second, sizeof(received_second) },
    };
    struct msghdr send_message = { 0 };
    struct msghdr receive_message = { 0 };
    struct msghdr too_large = { 0 };
    struct msghdr failed_receive = { 0 };
    struct cmsghdr *control_header;
    struct cmsghdr *received_header;
    int pair[2] = { -1, -1 };
    int received_descriptor = -1;
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 || pair[0] < 0 ||
        pair[1] < 0) {
        status = 1;
        goto finish;
    }
    control_header = (struct cmsghdr *)(void *)send_control;
    control_header->cmsg_len = CMSG_LEN(sizeof(pair[0]));
    control_header->__pad1 = -1;
    control_header->cmsg_level = SOL_SOCKET;
    control_header->cmsg_type = SCM_RIGHTS;
    copy_bytes(CMSG_DATA(control_header), &pair[0], sizeof(pair[0]));

    send_message.msg_iov = send_iov;
    send_message.msg_iovlen = 2;
    send_message.__pad1 = -1;
    send_message.msg_control = send_control;
    send_message.msg_controllen = sizeof(send_control);
    send_message.__pad2 = -1;
    errno = ERANGE;
    if (sendmsg(pair[0], &send_message, 0) != sizeof(expected) - 1 ||
        errno != ERANGE) {
        status = 2;
        goto finish;
    }

    receive_message.msg_iov = receive_iov;
    receive_message.msg_iovlen = 2;
    receive_message.__pad1 = -1;
    receive_message.msg_control = receive_control;
    receive_message.msg_controllen = sizeof(receive_control);
    receive_message.__pad2 = -1;
    errno = EINTR;
    if (recvmsg(pair[1], &receive_message, 0) != sizeof(expected) - 1 ||
        !bytes_equal(received_first, expected, sizeof(received_first)) ||
        !bytes_equal(received_second, expected + sizeof(received_first),
            sizeof(received_second)) || receive_message.__pad1 != 0 ||
        receive_message.__pad2 != 0 || errno != EINTR) {
        status = 3;
        goto finish;
    }
    received_header = CMSG_FIRSTHDR(&receive_message);
    if (received_header == 0 || received_header->cmsg_level != SOL_SOCKET ||
        received_header->cmsg_type != SCM_RIGHTS ||
        received_header->cmsg_len < CMSG_LEN(sizeof(received_descriptor))) {
        status = 4;
        goto finish;
    }
    copy_bytes(&received_descriptor, CMSG_DATA(received_header),
        sizeof(received_descriptor));
    if (raw_getfd(received_descriptor) < 0) {
        status = 5;
        goto finish;
    }

    /* The source bound is checked before musl reads msg_control. */
    too_large.msg_controllen = 1057;
    errno = 0;
    if (sendmsg(pair[0], &too_large, 0) != -1 || errno != ENOMEM) {
        status = 6;
        goto finish;
    }

    /* recvmsg copies the sanitised temporary header back on an error path. */
    failed_receive.__pad1 = -1;
    failed_receive.__pad2 = -1;
    errno = 0;
    if (recvmsg(-1, &failed_receive, 0) != -1 || errno != EBADF ||
        failed_receive.__pad1 != 0 || failed_receive.__pad2 != 0) {
        status = 7;
    }

finish:
    raw_close(received_descriptor);
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_rights_flags_and_truncation(void)
{
    static const char payload = 'r';
    char received = 0;
    unsigned char send_control[CMSG_SPACE(2 * sizeof(int))] = { 0 };
    unsigned char receive_control[CMSG_SPACE(2 * sizeof(int))] = { 0 };
    struct iovec send_iov = { (void *)&payload, 1 };
    struct iovec receive_iov = { &received, 1 };
    struct msghdr send_message = { 0 };
    struct msghdr receive_message = { 0 };
    struct cmsghdr *sent_header = (struct cmsghdr *)(void *)send_control;
    struct cmsghdr *received_header;
    int pair[2] = { -1, -1 };
    int passed[2] = { -1, -1 };
    int status = 0;
    int index;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    sent_header->cmsg_len = CMSG_LEN(sizeof(pair));
    sent_header->__pad1 = -1;
    sent_header->cmsg_level = SOL_SOCKET;
    sent_header->cmsg_type = SCM_RIGHTS;
    copy_bytes(CMSG_DATA(sent_header), pair, sizeof(pair));
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    send_message.__pad1 = -1;
    send_message.msg_control = send_control;
    send_message.msg_controllen = sizeof(send_control);
    send_message.__pad2 = -1;
    receive_message.msg_iov = &receive_iov;
    receive_message.msg_iovlen = 1;
    receive_message.__pad1 = -1;
    receive_message.msg_control = receive_control;
    receive_message.msg_controllen = sizeof(receive_control);
    receive_message.__pad2 = -1;

    if (sendmsg(pair[0], &send_message, 0) != 1) {
        status = 21;
        goto finish;
    }
    if (recvmsg(pair[1], &receive_message, MSG_CMSG_CLOEXEC) != 1) {
        status = 22;
        goto finish;
    }
    if (received != payload) {
        status = 23;
        goto finish;
    }
    if (receive_message.msg_flags & MSG_CTRUNC) {
        status = 24;
        goto finish;
    }
    if (receive_message.msg_controllen != CMSG_LEN(sizeof(pair))) {
        status = 25;
        goto finish;
    }
    received_header = CMSG_FIRSTHDR(&receive_message);
    if (!received_header || received_header->cmsg_level != SOL_SOCKET ||
        received_header->cmsg_type != SCM_RIGHTS ||
        received_header->cmsg_len != CMSG_LEN(sizeof(pair))) {
        status = 3;
        goto finish;
    }
    copy_bytes(passed, CMSG_DATA(received_header), sizeof(passed));
    for (index = 0; index < 2; ++index) {
        if (passed[index] < 0 || raw_getfd(passed[index]) != FD_CLOEXEC) {
            status = 4;
            goto finish;
        }
    }
    raw_close(passed[0]);
    raw_close(passed[1]);
    passed[0] = passed[1] = -1;

    /* One descriptor fits; Linux reports that the second was discarded. */
    receive_message.msg_controllen = CMSG_LEN(sizeof(int));
    receive_message.msg_flags = 0;
    received = 0;
    if (sendmsg(pair[0], &send_message, 0) != 1 ||
        recvmsg(pair[1], &receive_message, MSG_CMSG_CLOEXEC) != 1 ||
        received != payload || !(receive_message.msg_flags & MSG_CTRUNC) ||
        receive_message.msg_controllen != CMSG_LEN(sizeof(int))) {
        status = 5;
        goto finish;
    }
    received_header = CMSG_FIRSTHDR(&receive_message);
    if (!received_header || received_header->cmsg_level != SOL_SOCKET ||
        received_header->cmsg_type != SCM_RIGHTS ||
        received_header->cmsg_len != CMSG_LEN(sizeof(int))) {
        status = 6;
        goto finish;
    }
    copy_bytes(&passed[0], CMSG_DATA(received_header), sizeof(passed[0]));
    if (passed[0] < 0 || raw_getfd(passed[0]) != FD_CLOEXEC)
        status = 7;

finish:
    raw_close(passed[1]);
    raw_close(passed[0]);
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_rights_peek_and_discard(void)
{
    static const char payload[] = "rights";
    char received[sizeof(payload)] = { 0 };
    unsigned char send_control[CMSG_SPACE(2 * sizeof(int))] = { 0 };
    unsigned char receive_control[CMSG_SPACE(2 * sizeof(int))] = { 0 };
    struct iovec send_iov = { (void *)payload, sizeof(payload) };
    struct iovec receive_iov = { received, sizeof(received) };
    struct msghdr send_message = { 0 };
    struct msghdr receive_message = { 0 };
    struct cmsghdr *header = (struct cmsghdr *)(void *)send_control;
    int pair[2] = { -1, -1 };
    int passed[2] = { -1, -1 };
    int baseline;
    int status = 0;
    int index;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    baseline = open_descriptor_count();
    header->cmsg_len = CMSG_LEN(sizeof(pair));
    header->__pad1 = -1;
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    copy_bytes(CMSG_DATA(header), pair, sizeof(pair));
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    send_message.__pad1 = -1;
    send_message.msg_control = send_control;
    send_message.msg_controllen = sizeof(send_control);
    send_message.__pad2 = -1;
    receive_message.msg_iov = &receive_iov;
    receive_message.msg_iovlen = 1;
    receive_message.msg_control = receive_control;

    if (sendmsg(pair[0], &send_message, 0) != sizeof(payload)) {
        status = 2;
        goto finish;
    }
    for (index = 0; index < 2; ++index) {
        struct cmsghdr *received_header;

        receive_message.msg_controllen = sizeof(receive_control);
        receive_message.msg_flags = 0;
        receive_message.__pad1 = -1;
        receive_message.__pad2 = -1;
        if (recvmsg(pair[1], &receive_message,
                MSG_PEEK | MSG_CMSG_CLOEXEC) != sizeof(payload)) {
            status = 3;
            goto finish;
        }
        if (!bytes_equal(received, payload, sizeof(payload))) {
            status = 9;
            goto finish;
        }
        if (receive_message.msg_flags != MSG_CMSG_CLOEXEC) {
            status = 10;
            goto finish;
        }
        if (receive_message.msg_controllen != CMSG_LEN(sizeof(pair))) {
            status = 11;
            goto finish;
        }
        if (receive_message.__pad1 != 0 || receive_message.__pad2 != 0) {
            status = 12;
            goto finish;
        }
        received_header = CMSG_FIRSTHDR(&receive_message);
        if (!received_header || received_header->cmsg_level != SOL_SOCKET ||
            received_header->cmsg_type != SCM_RIGHTS ||
            received_header->cmsg_len != CMSG_LEN(sizeof(pair))) {
            status = 4;
            goto finish;
        }
        copy_bytes(passed, CMSG_DATA(received_header), sizeof(passed));
        if (passed[0] < 0 || passed[1] < 0 || passed[0] == passed[1] ||
            raw_getfd(passed[0]) != FD_CLOEXEC ||
            raw_getfd(passed[1]) != FD_CLOEXEC) {
            status = 5;
            goto finish;
        }
        raw_close(passed[0]);
        raw_close(passed[1]);
        passed[0] = passed[1] = -1;
        if (open_descriptor_count() != baseline) {
            status = 6;
            goto finish;
        }
    }

    /* No control storage discards both pending rights without installing fds. */
    receive_message.msg_control = 0;
    receive_message.msg_controllen = 0;
    receive_message.msg_flags = 0;
    receive_message.__pad1 = -1;
    receive_message.__pad2 = -1;
    if (recvmsg(pair[1], &receive_message, MSG_CMSG_CLOEXEC) !=
            sizeof(payload) ||
        !(receive_message.msg_flags & MSG_CTRUNC) ||
        receive_message.msg_controllen != 0 ||
        receive_message.__pad1 != 0 || receive_message.__pad2 != 0 ||
        open_descriptor_count() != baseline) {
        status = 7;
        goto finish;
    }

    /* A nonblocking error still copies back the sanitized public header. */
    receive_message.msg_control = receive_control;
    receive_message.msg_controllen = sizeof(receive_control);
    receive_message.msg_flags = 0x1234;
    receive_message.__pad1 = -1;
    receive_message.__pad2 = -1;
    errno = 0;
    if (recvmsg(pair[1], &receive_message, MSG_DONTWAIT) != -1 ||
        errno != EAGAIN || receive_message.msg_flags != 0x1234 ||
        receive_message.msg_controllen != sizeof(receive_control) ||
        receive_message.__pad1 != 0 || receive_message.__pad2 != 0 ||
        open_descriptor_count() != baseline) {
        status = 8;
        goto finish;
    }

    /* Data truncation returns the datagram length while ancillary rights survive. */
    receive_iov.iov_len = 2;
    receive_message.msg_controllen = sizeof(receive_control);
    receive_message.msg_flags = 0;
    receive_message.__pad1 = -1;
    receive_message.__pad2 = -1;
    if (sendmsg(pair[0], &send_message, 0) != sizeof(payload) ||
        recvmsg(pair[1], &receive_message,
            MSG_TRUNC | MSG_CMSG_CLOEXEC) != sizeof(payload) ||
        !bytes_equal(received, payload, 2) ||
        receive_message.msg_flags != (MSG_TRUNC | MSG_CMSG_CLOEXEC) ||
        receive_message.msg_controllen != CMSG_LEN(sizeof(pair)) ||
        receive_message.__pad1 != 0 || receive_message.__pad2 != 0) {
        status = 13;
        goto finish;
    }
    header = CMSG_FIRSTHDR(&receive_message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(pair))) {
        status = 14;
        goto finish;
    }
    copy_bytes(passed, CMSG_DATA(header), sizeof(passed));
    if (passed[0] < 0 || passed[1] < 0 || passed[0] == passed[1] ||
        raw_getfd(passed[0]) != FD_CLOEXEC ||
        raw_getfd(passed[1]) != FD_CLOEXEC) {
        status = 15;
        goto finish;
    }
    raw_close(passed[0]);
    raw_close(passed[1]);
    passed[0] = passed[1] = -1;
    if (open_descriptor_count() != baseline) {
        status = 16;
    }

finish:
    raw_close(passed[1]);
    raw_close(passed[0]);
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_rights_limit_and_discard(void)
{
    static const char payload = 'm';
    char received = 0;
    unsigned char send_control[CMSG_SPACE(254 * sizeof(int))] = { 0 };
    unsigned char receive_control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct iovec send_iov = { (void *)&payload, 1 };
    struct iovec receive_iov = { &received, 1 };
    struct msghdr send_message = { 0 };
    struct msghdr receive_message = { 0 };
    struct cmsghdr *header = (struct cmsghdr *)(void *)send_control;
    int rights[254];
    int pair[2] = { -1, -1 };
    int passed = -1;
    int baseline;
    int status = 0;
    int index;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    baseline = open_descriptor_count();
    for (index = 0; index < 254; ++index)
        rights[index] = pair[0];
    header->cmsg_len = CMSG_LEN(sizeof(rights));
    header->__pad1 = -1;
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    copy_bytes(CMSG_DATA(header), rights, sizeof(rights));
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    send_message.__pad1 = -1;
    send_message.msg_control = send_control;
    send_message.msg_controllen = sizeof(send_control);
    send_message.__pad2 = -1;
    receive_message.msg_iov = &receive_iov;
    receive_message.msg_iovlen = 1;
    receive_message.msg_control = receive_control;
    receive_message.msg_controllen = CMSG_LEN(sizeof(int));

    errno = 0;
    if (sendmsg(pair[0], &send_message, 0) != -1 || errno != EINVAL ||
        open_descriptor_count() != baseline) {
        status = 2;
        goto finish;
    }
    errno = 0;
    if (recvmsg(pair[1], &receive_message, MSG_DONTWAIT) != -1 ||
        errno != EAGAIN) {
        status = 3;
        goto finish;
    }

    /* Linux accepts 253 rights, then closes those excluded by control capacity. */
    header->cmsg_len = CMSG_LEN(253 * sizeof(int));
    send_message.msg_controllen = CMSG_SPACE(253 * sizeof(int));
    receive_message.msg_controllen = CMSG_LEN(sizeof(int));
    receive_message.msg_flags = 0;
    errno = ERANGE;
    if (sendmsg(pair[0], &send_message, 0) != 1 || errno != ERANGE) {
        status = 4;
        goto finish;
    }
    if (recvmsg(pair[1], &receive_message, MSG_CMSG_CLOEXEC) != 1) {
        status = 8;
        goto finish;
    }
    if (received != payload) {
        status = 9;
        goto finish;
    }
    if (receive_message.msg_flags != (MSG_CTRUNC | MSG_CMSG_CLOEXEC)) {
        status = 10;
        goto finish;
    }
    if (receive_message.msg_controllen != CMSG_LEN(sizeof(int))) {
        status = 11;
        goto finish;
    }
    header = CMSG_FIRSTHDR(&receive_message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) {
        status = 5;
        goto finish;
    }
    copy_bytes(&passed, CMSG_DATA(header), sizeof(passed));
    if (passed < 0 || raw_getfd(passed) != FD_CLOEXEC) {
        status = 6;
        goto finish;
    }
    raw_close(passed);
    passed = -1;
    if (open_descriptor_count() != baseline)
        status = 7;

finish:
    raw_close(passed);
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_mmsg(void)
{
    static const char first[] = "one";
    static const char second[] = "two";
    char received_first[sizeof(first) - 1] = { 0 };
    char received_second[sizeof(second) - 1] = { 0 };
    struct iovec send_iov[2] = {
        { (void *)first, sizeof(first) - 1 },
        { (void *)second, sizeof(second) - 1 },
    };
    struct iovec receive_iov[2] = {
        { received_first, sizeof(received_first) },
        { received_second, sizeof(received_second) },
    };
    struct mmsghdr invalid_message = { 0 };
    struct mmsghdr send_messages[2] = { 0 };
    struct mmsghdr receive_messages[2] = { 0 };
    int pair[2] = { -1, -1 };
    int status = 0;

    errno = ERANGE;
    if (sendmmsg(-1, 0, 0, 0) != 0 || errno != ERANGE)
        return 1;
    errno = 0;
    if (sendmmsg(-1, &invalid_message, 1, 0) != -1 || errno != EBADF)
        return 2;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0 || pair[0] < 0 ||
        pair[1] < 0) {
        status = 3;
        goto finish;
    }
    send_messages[0].msg_hdr.msg_iov = &send_iov[0];
    send_messages[0].msg_hdr.msg_iovlen = 1;
    send_messages[0].msg_hdr.__pad1 = -1;
    send_messages[0].msg_hdr.__pad2 = -1;
    send_messages[1].msg_hdr.msg_iov = &send_iov[1];
    send_messages[1].msg_hdr.msg_iovlen = 1;
    send_messages[1].msg_hdr.__pad1 = -1;
    send_messages[1].msg_hdr.__pad2 = -1;
    errno = EINTR;
    if (sendmmsg(pair[0], send_messages, 2, 0) != 2 ||
        send_messages[0].msg_len != sizeof(first) - 1 ||
        send_messages[1].msg_len != sizeof(second) - 1 || errno != EINTR) {
        status = 4;
        goto finish;
    }

    receive_messages[0].msg_hdr.msg_iov = &receive_iov[0];
    receive_messages[0].msg_hdr.msg_iovlen = 1;
    receive_messages[0].msg_hdr.__pad1 = -1;
    receive_messages[0].msg_hdr.__pad2 = -1;
    receive_messages[1].msg_hdr.msg_iov = &receive_iov[1];
    receive_messages[1].msg_hdr.msg_iovlen = 1;
    receive_messages[1].msg_hdr.__pad1 = -1;
    receive_messages[1].msg_hdr.__pad2 = -1;
    errno = ERANGE;
    if (recvmmsg(pair[1], receive_messages, 2, 0, 0) != 2 ||
        receive_messages[0].msg_len != sizeof(first) - 1 ||
        receive_messages[1].msg_len != sizeof(second) - 1 ||
        !bytes_equal(received_first, first, sizeof(received_first)) ||
        !bytes_equal(received_second, second, sizeof(received_second)) ||
        receive_messages[0].msg_hdr.__pad1 != 0 ||
        receive_messages[0].msg_hdr.__pad2 != 0 ||
        receive_messages[1].msg_hdr.__pad1 != 0 ||
        receive_messages[1].msg_hdr.__pad2 != 0 || errno != ERANGE) {
        status = 5;
        goto finish;
    }

    /* A later preflight failure preserves the first datagram and its length. */
    send_messages[0].msg_len = 0;
    send_messages[1].msg_len = 77;
    send_messages[1].msg_hdr.msg_control = (void *)(uintptr_t)1;
    send_messages[1].msg_hdr.msg_controllen = 1057;
    errno = 0;
    if (sendmmsg(pair[0], send_messages, 2, 0) != 1 || errno != ENOMEM ||
        send_messages[0].msg_len != sizeof(first) - 1 ||
        send_messages[1].msg_len != 77) {
        status = 6;
        goto finish;
    }
    receive_messages[0].msg_hdr.msg_controllen = 0;
    receive_messages[0].msg_hdr.msg_flags = 0;
    if (recvmsg(pair[1], &receive_messages[0].msg_hdr, MSG_DONTWAIT) !=
            sizeof(first) - 1 ||
        !bytes_equal(received_first, first, sizeof(received_first))) {
        status = 7;
        goto finish;
    }
    errno = 0;
    if (recvmsg(pair[1], &receive_messages[0].msg_hdr, MSG_DONTWAIT) != -1 ||
        errno != EAGAIN) {
        status = 8;
    }

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_zero_length_and_error_precedence(void)
{
    static const char payload[] = "zero";
    struct iovec send_iov = { (void *)payload, sizeof(payload) - 1 };
    struct msghdr empty = { 0 };
    struct msghdr receive = { 0 };
    struct msghdr oversized = { 0 };
    int pair[2] = { -1, -1 };
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    empty.msg_iov = (struct iovec *)(uintptr_t)1;
    empty.__pad1 = -1;
    empty.__pad2 = -1;
    errno = ERANGE;
    if (sendmsg(pair[0], &empty, 0) != 0 || errno != ERANGE) {
        status = 2;
        goto finish;
    }
    receive.msg_iov = (struct iovec *)(uintptr_t)1;
    receive.__pad1 = -1;
    receive.__pad2 = -1;
    errno = EINTR;
    if (recvmsg(pair[1], &receive, MSG_TRUNC) != 0 ||
        receive.msg_flags != 0 || receive.__pad1 != 0 ||
        receive.__pad2 != 0 || errno != EINTR) {
        status = 3;
        goto finish;
    }
    empty.msg_iov = &send_iov;
    empty.msg_iovlen = 1;
    if (sendmsg(pair[0], &empty, 0) != sizeof(payload) - 1) {
        status = 4;
        goto finish;
    }
    receive.__pad1 = -1;
    receive.__pad2 = -1;
    if (recvmsg(pair[1], &receive, MSG_TRUNC) != sizeof(payload) - 1 ||
        receive.msg_flags != MSG_TRUNC || receive.__pad1 != 0 ||
        receive.__pad2 != 0) {
        status = 5;
        goto finish;
    }

    /* The bounded outgoing control copy rejects length before entering Linux. */
    oversized.msg_control = (void *)(uintptr_t)1;
    oversized.msg_controllen = 1057;
    errno = 0;
    if (sendmsg(-1, &oversized, 0) != -1 || errno != ENOMEM) {
        status = 6;
        goto finish;
    }
    errno = 0;
    if (sendmsg(-1, 0, 0) != -1 || errno != EBADF) {
        status = 7;
        goto finish;
    }
    receive.msg_iov = (struct iovec *)(uintptr_t)1;
    receive.msg_iovlen = 1;
    errno = 0;
    if (recvmsg(-1, &receive, 0) != -1 || errno != EBADF) {
        status = 8;
        goto finish;
    }
    errno = 0;
    if (sendmsg(-1, &empty, MSG_OOB) != -1 || errno != EBADF) {
        status = 9;
        goto finish;
    }
    errno = 0;
    if (sendmsg(pair[0], &empty, MSG_OOB) != -1 ||
        errno != EOPNOTSUPP) {
        status = 10;
        goto finish;
    }

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_credentials(void)
{
    static const char payload = 'c';
    char received = 0;
    unsigned char control[CMSG_SPACE(sizeof(struct ucred))] = { 0 };
    struct iovec send_iov = { (void *)&payload, 1 };
    struct iovec receive_iov = { &received, 1 };
    struct msghdr send_message = { 0 };
    struct msghdr receive_message = { 0 };
    struct cmsghdr *header;
    struct ucred credentials;
    int pair[2] = { -1, -1 };
    int passcred = 1;
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    if (setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &passcred,
            sizeof(passcred)) != 0) {
        status = 2;
        goto finish;
    }
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    send_message.__pad1 = -1;
    send_message.__pad2 = -1;
    receive_message.msg_iov = &receive_iov;
    receive_message.msg_iovlen = 1;
    receive_message.__pad1 = -1;
    receive_message.msg_control = control;
    receive_message.msg_controllen = sizeof(control);
    receive_message.__pad2 = -1;
    errno = ERANGE;
    if (sendmsg(pair[0], &send_message, 0) != 1) {
        status = 3;
        goto finish;
    }
    if (recvmsg(pair[1], &receive_message, 0) != 1) {
        status = 6;
        goto finish;
    }
    if (received != payload || errno != ERANGE) {
        status = 7;
        goto finish;
    }
    if (receive_message.msg_flags != 0) {
        status = 8;
        goto finish;
    }
    if (receive_message.msg_controllen != CMSG_SPACE(sizeof(struct ucred))) {
        status = 9;
        goto finish;
    }
    if (receive_message.__pad1 != 0 || receive_message.__pad2 != 0) {
        status = 10;
        goto finish;
    }
    header = CMSG_FIRSTHDR(&receive_message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_CREDENTIALS ||
        header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
        status = 4;
        goto finish;
    }
    copy_bytes(&credentials, CMSG_DATA(header), sizeof(credentials));
    if (credentials.pid != raw1(SYS_getpid, 0) ||
        credentials.uid != raw1(SYS_getuid, 0) ||
        credentials.gid != raw1(SYS_getgid, 0)) {
        status = 5;
    }

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

static int check_sockatmark(void)
{
    int pair[2] = { -1, -1 };
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 || pair[0] < 0 ||
        pair[1] < 0) {
        status = 1;
        goto finish;
    }
    errno = ERANGE;
    if (sockatmark(pair[0]) < 0 || errno != ERANGE) {
        status = 2;
        goto finish;
    }
    errno = 0;
    if (sockatmark(-1) != -1 || errno != EBADF)
        status = 3;

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    return status;
}

int crabc_x86_64_socket_messages_probe(void)
{
    int result;

    result = check_socket_options();
    if (result != 0)
        return 10 + result;
    result = check_sendmsg_recvmsg();
    if (result != 0)
        return 30 + result;
    result = check_rights_flags_and_truncation();
    if (result != 0)
        return 40 + result;
    result = check_rights_peek_and_discard();
    if (result != 0)
        return 80 + result;
    result = check_rights_limit_and_discard();
    if (result != 0)
        return 110 + result;
    result = check_mmsg();
    if (result != 0)
        return 50 + result;
    result = check_zero_length_and_error_precedence();
    if (result != 0)
        return 140 + result;
    result = check_credentials();
    if (result != 0)
        return 150 + result;
    result = check_sockatmark();
    if (result != 0)
        return 70 + result;
    return 0;
}

#ifndef CRABC_SOCKET_MESSAGES_FREESTANDING
int main(void)
{
    return crabc_x86_64_socket_messages_probe();
}
#endif
