/* Static crabc-libc x86-64 selected socket transport fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * `libc.a`. It selects only the closed socket lifecycle and byte-transport
 * surface below. AF_UNIX socketpair traffic proves send/recv/shutdown without
 * a namespace, while AF_INET loopback UDP and TCP prove the address-bearing
 * operations locally. Fixture-local raw close and fcntl calls only clean up
 * descriptors and observe atomic descriptor flags; they do not select C
 * fcntl/open/path APIs, socket options, ioctl/interface support, message or
 * vector I/O, resolver/netdb, pthread cancellation, libc.so, CRT, or loader.
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
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(socklen_t) == 4 && _Alignof(socklen_t) == 4 &&
    sizeof(ssize_t) == 8, "x86 socket scalar widths");
_Static_assert(sizeof(struct sockaddr) == 16 && _Alignof(struct sockaddr) == 2 &&
    offsetof(struct sockaddr, sa_family) == 0 &&
    offsetof(struct sockaddr, sa_data) == 2,
    "x86 sockaddr layout");
_Static_assert(sizeof(struct sockaddr_storage) == 128 &&
    _Alignof(struct sockaddr_storage) == 8 &&
    offsetof(struct sockaddr_storage, ss_family) == 0,
    "x86 sockaddr_storage layout");
_Static_assert(sizeof(struct sockaddr_in) == 16 &&
    _Alignof(struct sockaddr_in) == 4 &&
    offsetof(struct sockaddr_in, sin_family) == 0 &&
    offsetof(struct sockaddr_in, sin_port) == 2 &&
    offsetof(struct sockaddr_in, sin_addr) == 4 &&
    offsetof(struct sockaddr_in, sin_zero) == 8,
    "x86 sockaddr_in layout");
_Static_assert(AF_UNIX == 1 && AF_INET == 2 && SOCK_STREAM == 1 &&
    SOCK_DGRAM == 2 && SOCK_CLOEXEC == 02000000 && SOCK_NONBLOCK == 04000 &&
    SHUT_WR == 1,
    "x86 selected socket constants");
_Static_assert(SYS_socket == 41 && SYS_connect == 42 && SYS_accept == 43 &&
    SYS_sendto == 44 && SYS_recvfrom == 45 && SYS_shutdown == 48 &&
    SYS_bind == 49 && SYS_listen == 50 && SYS_getsockname == 51 &&
    SYS_getpeername == 52 && SYS_socketpair == 53 && SYS_accept4 == 288,
    "x86 selected socket syscall numbers");
_Static_assert(SYS_close == 3 && SYS_fcntl == 72,
    "x86 fixture-only descriptor syscall numbers");
_Static_assert(F_GETFD == 1 && F_GETFL == 3 && FD_CLOEXEC == 1 &&
    O_NONBLOCK == 04000,
    "x86 fixture-only descriptor constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&socket),
    int (*)(int, int, int)), "socket declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&socketpair),
    int (*)(int, int, int, int *)), "socketpair declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bind),
    int (*)(int, const struct sockaddr *, socklen_t)), "bind declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&listen),
    int (*)(int, int)), "listen declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&accept),
    int (*)(int, struct sockaddr *, socklen_t *)), "accept declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&accept4),
    int (*)(int, struct sockaddr *, socklen_t *, int)), "accept4 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&connect),
    int (*)(int, const struct sockaddr *, socklen_t)), "connect declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&send),
    ssize_t (*)(int, const void *, size_t, int)), "send declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recv),
    ssize_t (*)(int, void *, size_t, int)), "recv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendto),
    ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *,
        socklen_t)), "sendto declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvfrom),
    ssize_t (*)(int, void *, size_t, int, struct sockaddr *, socklen_t *)),
    "recvfrom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shutdown),
    int (*)(int, int)), "shutdown declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getsockname),
    int (*)(int, struct sockaddr *, socklen_t *)), "getsockname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpeername),
    int (*)(int, struct sockaddr *, socklen_t *)), "getpeername declaration");

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

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

static void raw_close(int file_descriptor)
{
    if (file_descriptor >= 0)
        (void)raw_syscall1(SYS_close, file_descriptor);
}

static int raw_getfd(int file_descriptor)
{
    return (int)raw_syscall3(SYS_fcntl, file_descriptor, F_GETFD, 0);
}

static int raw_getfl(int file_descriptor)
{
    return (int)raw_syscall3(SYS_fcntl, file_descriptor, F_GETFL, 0);
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static struct sockaddr_in loopback_address(void)
{
    struct sockaddr_in address = { 0 };

    address.sin_family = AF_INET;
    /* 127.0.0.1 in network byte order, stored as an x86 little-endian word. */
    address.sin_addr.s_addr = 0x0100007fU;
    return address;
}

static int check_unix_pair(void)
{
    int cloexec_socket = -1;
    int cloexec_pair[2] = { -1, -1 };
    int pair[2] = { -1, -1 };
    char received[2] = { 0, 0 };
    int status = 0;

    /* Linux 5.10 accepts both flags atomically; no fcntl fallback exists. */
    cloexec_socket = socket(AF_UNIX,
        SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (cloexec_socket < 0 || raw_getfd(cloexec_socket) != FD_CLOEXEC ||
        (raw_getfl(cloexec_socket) & O_NONBLOCK) == 0) {
        status = 1;
        goto finish;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
            cloexec_pair) != 0 ||
        cloexec_pair[0] < 0 || cloexec_pair[1] < 0 ||
        raw_getfd(cloexec_pair[0]) != FD_CLOEXEC ||
        raw_getfd(cloexec_pair[1]) != FD_CLOEXEC ||
        (raw_getfl(cloexec_pair[0]) & O_NONBLOCK) == 0 ||
        (raw_getfl(cloexec_pair[1]) & O_NONBLOCK) == 0) {
        status = 2;
        goto finish;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
        pair[0] < 0 || pair[1] < 0) {
        status = 3;
        goto finish;
    }
    if (send(pair[0], "uv", 2, 0) != 2 ||
        recv(pair[1], received, sizeof(received), 0) != 2 ||
        !bytes_equal(received, "uv", sizeof(received))) {
        status = 4;
        goto finish;
    }
    if (shutdown(pair[0], SHUT_WR) != 0 || recv(pair[1], received, 1, 0) != 0)
        status = 5;

finish:
    raw_close(pair[1]);
    raw_close(pair[0]);
    raw_close(cloexec_pair[1]);
    raw_close(cloexec_pair[0]);
    raw_close(cloexec_socket);
    return status;
}

static int check_loopback_datagram(void)
{
    int receiver = -1;
    int sender = -1;
    struct sockaddr_in bound = loopback_address();
    struct sockaddr_in source = { 0 };
    socklen_t bound_length = sizeof(bound);
    socklen_t source_length = sizeof(source);
    char received[3] = { 0, 0, 0 };
    int status = 0;

    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0 || sender < 0) {
        status = 1;
        goto finish;
    }
    if (bind(receiver, (const struct sockaddr *)&bound, sizeof(bound)) != 0 ||
        getsockname(receiver, (struct sockaddr *)&bound, &bound_length) != 0 ||
        bound_length != sizeof(bound) || bound.sin_family != AF_INET ||
        bound.sin_addr.s_addr != 0x0100007fU || bound.sin_port == 0) {
        status = 2;
        goto finish;
    }
    if (sendto(sender, "udp", 3, 0, (const struct sockaddr *)&bound,
            sizeof(bound)) != 3 ||
        recvfrom(receiver, received, sizeof(received), 0,
            (struct sockaddr *)&source, &source_length) != 3 ||
        !bytes_equal(received, "udp", sizeof(received)) ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_addr.s_addr != 0x0100007fU || source.sin_port == 0) {
        status = 3;
    }

finish:
    raw_close(sender);
    raw_close(receiver);
    return status;
}

static int check_loopback_stream(void)
{
    int listener = -1;
    int first_client = -1;
    int second_client = -1;
    int first_peer = -1;
    int second_peer = -1;
    struct sockaddr_in listener_address = loopback_address();
    struct sockaddr_in peer_address = { 0 };
    socklen_t listener_length = sizeof(listener_address);
    socklen_t peer_length = sizeof(peer_address);
    int status = 0;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 ||
        bind(listener, (const struct sockaddr *)&listener_address,
            sizeof(listener_address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&listener_address,
            &listener_length) != 0 ||
        listener_length != sizeof(listener_address) ||
        listener_address.sin_family != AF_INET || listener_address.sin_port == 0 ||
        listen(listener, 2) != 0) {
        status = 1;
        goto finish;
    }

    first_client = socket(AF_INET, SOCK_STREAM, 0);
    if (first_client < 0 ||
        connect(first_client, (const struct sockaddr *)&listener_address,
            sizeof(listener_address)) != 0) {
        status = 2;
        goto finish;
    }
    first_peer = accept(listener, (struct sockaddr *)&peer_address, &peer_length);
    if (first_peer < 0 || peer_length != sizeof(peer_address) ||
        peer_address.sin_family != AF_INET ||
        peer_address.sin_addr.s_addr != 0x0100007fU || peer_address.sin_port == 0) {
        status = 3;
        goto finish;
    }
    peer_length = sizeof(peer_address);
    if (getpeername(first_peer, (struct sockaddr *)&peer_address, &peer_length) != 0 ||
        peer_length != sizeof(peer_address) || peer_address.sin_family != AF_INET ||
        peer_address.sin_addr.s_addr != 0x0100007fU || peer_address.sin_port == 0) {
        status = 4;
        goto finish;
    }

    second_client = socket(AF_INET, SOCK_STREAM, 0);
    if (second_client < 0 ||
        connect(second_client, (const struct sockaddr *)&listener_address,
            sizeof(listener_address)) != 0) {
        status = 5;
        goto finish;
    }
    peer_length = sizeof(peer_address);
    second_peer = accept4(listener, (struct sockaddr *)&peer_address,
        &peer_length, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (second_peer < 0 || peer_length != sizeof(peer_address) ||
        peer_address.sin_family != AF_INET ||
        peer_address.sin_addr.s_addr != 0x0100007fU || peer_address.sin_port == 0 ||
        raw_getfd(second_peer) != FD_CLOEXEC ||
        (raw_getfl(second_peer) & O_NONBLOCK) == 0) {
        status = 6;
    }

finish:
    raw_close(second_peer);
    raw_close(first_peer);
    raw_close(second_client);
    raw_close(first_client);
    raw_close(listener);
    return status;
}

static int check_error_translation(void)
{
    struct sockaddr_in address = loopback_address();
    socklen_t address_length = sizeof(address);
    char byte = 0;

    errno = 0;
    if (socket(AF_INET, -1, 0) != -1 || errno != EINVAL)
        return 1;
    errno = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, NULL) != -1 || errno != EFAULT)
        return 2;
    errno = 0;
    if (bind(-1, (const struct sockaddr *)&address, sizeof(address)) != -1 ||
        errno != EBADF)
        return 3;
    errno = 0;
    if (listen(-1, 1) != -1 || errno != EBADF)
        return 4;
    errno = 0;
    if (accept(-1, (struct sockaddr *)&address, &address_length) != -1 ||
        errno != EBADF)
        return 5;
    errno = 0;
    if (accept4(-1, (struct sockaddr *)&address, &address_length, 0) != -1 ||
        errno != EBADF)
        return 6;
    errno = 0;
    if (connect(-1, (const struct sockaddr *)&address, sizeof(address)) != -1 ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (send(-1, &byte, 1, 0) != -1 || errno != EBADF)
        return 8;
    errno = 0;
    if (recv(-1, &byte, 1, 0) != -1 || errno != EBADF)
        return 9;
    errno = 0;
    if (sendto(-1, &byte, 1, 0, (const struct sockaddr *)&address,
            sizeof(address)) != -1 || errno != EBADF)
        return 10;
    errno = 0;
    if (recvfrom(-1, &byte, 1, 0, (struct sockaddr *)&address,
            &address_length) != -1 || errno != EBADF)
        return 11;
    errno = 0;
    if (shutdown(-1, SHUT_WR) != -1 || errno != EBADF)
        return 12;
    errno = 0;
    if (getsockname(-1, (struct sockaddr *)&address, &address_length) != -1 ||
        errno != EBADF)
        return 13;
    errno = 0;
    if (getpeername(-1, (struct sockaddr *)&address, &address_length) != -1 ||
        errno != EBADF)
        return 14;
    return 0;
}

int crabc_x86_64_socket_transport_probe(void)
{
    int status;

    status = check_unix_pair();
    if (status != 0)
        return 10 + status;
    status = check_loopback_datagram();
    if (status != 0)
        return 30 + status;
    status = check_loopback_stream();
    if (status != 0)
        return 50 + status;
    status = check_error_translation();
    if (status != 0)
        return 70 + status;
    return 0;
}

#ifndef CRABC_SOCKET_TRANSPORT_FREESTANDING
int main(void)
{
    return crabc_x86_64_socket_transport_probe();
}
#endif
