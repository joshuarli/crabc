/* Static crabc-libc x86-64 selected socket transport fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * `libc.a`. It selects only the closed socket lifecycle and byte-transport
 * surface below. AF_UNIX abstract names exercise stream/datagram address
 * lengths and descriptor lifetime without filesystem cleanup; socketpair and
 * AF_INET loopback traffic cover the remaining local paths. Fixture-local
 * raw close, getpid, write, and fcntl calls only manage and observe the probe;
 * they do not select C
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
#include <sys/un.h>

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
_Static_assert(sizeof(struct sockaddr_un) == 110 &&
    offsetof(struct sockaddr_un, sun_path) == 2,
    "x86 sockaddr_un layout");
_Static_assert(AF_UNIX == 1 && AF_INET == 2 && SOCK_STREAM == 1 &&
    SOCK_DGRAM == 2 && SOCK_CLOEXEC == 02000000 && SOCK_NONBLOCK == 04000 &&
    SHUT_WR == 1,
    "x86 selected socket constants");
_Static_assert(SYS_socket == 41 && SYS_connect == 42 && SYS_accept == 43 &&
    SYS_sendto == 44 && SYS_recvfrom == 45 && SYS_shutdown == 48 &&
    SYS_bind == 49 && SYS_listen == 50 && SYS_getsockname == 51 &&
    SYS_getpeername == 52 && SYS_socketpair == 53 && SYS_accept4 == 288,
    "x86 selected socket syscall numbers");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_getpid == 39 &&
    SYS_fcntl == 72,
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

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long r10 __asm__("r10") = argument4;
    register long r8 __asm__("r8") = argument5;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(r10), "r"(r8) : "rcx", "r11", "memory");
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

/* Every observed errno or address length is one tagged, two-digit hex row. */
static char unix_trace[512];
static size_t unix_trace_length;

static void trace_unix_value(char label, unsigned int value)
{
    static const char digits[] = "0123456789abcdef";

    unix_trace[unix_trace_length++] = label;
    unix_trace[unix_trace_length++] = ':';
    unix_trace[unix_trace_length++] = digits[(value >> 4) & 15];
    unix_trace[unix_trace_length++] = digits[value & 15];
    unix_trace[unix_trace_length++] = '\n';
}

static socklen_t abstract_unix_address(struct sockaddr_un *address, char kind)
{
    unsigned long pid = (unsigned long)raw_syscall1(SYS_getpid, 0);
    size_t index;

    *address = (struct sockaddr_un){ 0 };
    address->sun_family = AF_UNIX;
    address->sun_path[1] = 'c';
    address->sun_path[2] = 'r';
    address->sun_path[3] = 'b';
    address->sun_path[4] = kind;
    for (index = 0; index < 4; ++index)
        address->sun_path[5 + index] = (char)(pid >> (index * 8));
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 9);
}

static int check_unix_named_stream(void)
{
    struct sockaddr_un listener_address, client_address, absent_address;
    struct sockaddr_un observed = { 0 };
    socklen_t listener_length = abstract_unix_address(&listener_address, 's');
    socklen_t client_length = abstract_unix_address(&client_address, 'c');
    socklen_t absent_length = abstract_unix_address(&absent_address, 'x');
    socklen_t observed_length;
    int listener = -1, duplicate = -1, client = -1, peer = -1, probe = -1;
    int status = 0;
    char byte = 0;

    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    duplicate = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listener < 0 || duplicate < 0 || client < 0 || probe < 0) {
        status = 1;
        goto finish;
    }
    errno = 0;
    if (connect(probe, (const struct sockaddr *)&absent_address,
            absent_length) != -1 || errno != ECONNREFUSED) {
        status = 16;
        goto finish;
    }
    trace_unix_value('s', errno);
    errno = 0;
    if (bind(-1, NULL, 1) != -1 || errno != EBADF) {
        status = 2;
        goto finish;
    }
    trace_unix_value('a', errno);
    errno = 0;
    if (bind(listener, (const struct sockaddr *)&listener_address, 1) != -1 ||
        errno != EINVAL) {
        status = 3;
        goto finish;
    }
    trace_unix_value('b', errno);
    if (bind(listener, (const struct sockaddr *)&listener_address,
            listener_length) != 0) {
        status = 4;
        goto finish;
    }
    observed_length = sizeof(observed.sun_family);
    if (getsockname(listener, (struct sockaddr *)&observed,
            &observed_length) != 0 ||
        observed_length != listener_length || observed.sun_family != AF_UNIX) {
        status = 5;
        goto finish;
    }
    trace_unix_value('c', observed_length);
    errno = 0;
    if (bind(duplicate, (const struct sockaddr *)&listener_address,
            listener_length) != -1 || errno != EADDRINUSE) {
        status = 6;
        goto finish;
    }
    trace_unix_value('d', errno);
    if (listen(listener, 2) != 0) {
        status = 7;
        goto finish;
    }
    errno = 0;
    if (accept4(listener, NULL, NULL, SOCK_NONBLOCK) != -1 ||
        errno != EAGAIN) {
        status = 8;
        goto finish;
    }
    trace_unix_value('e', errno);
    errno = 0;
    if (accept4(listener, NULL, NULL, 0x40000000) != -1 ||
        errno != EINVAL) {
        status = 9;
        goto finish;
    }
    trace_unix_value('f', errno);
    if (bind(client, (const struct sockaddr *)&client_address,
            client_length) != 0 ||
        connect(client, (const struct sockaddr *)&listener_address,
            listener_length) != 0) {
        status = 10;
        goto finish;
    }
    observed_length = sizeof(observed.sun_family);
    peer = accept4(listener, (struct sockaddr *)&observed, &observed_length,
        SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (peer < 0 || observed_length != client_length ||
        observed.sun_family != AF_UNIX ||
        raw_getfd(peer) != FD_CLOEXEC ||
        (raw_getfl(peer) & O_NONBLOCK) == 0) {
        status = 11;
        goto finish;
    }
    trace_unix_value('g', observed_length);
    observed_length = sizeof(observed);
    if (getpeername(peer, (struct sockaddr *)&observed,
            &observed_length) != 0 || observed_length != client_length ||
        !bytes_equal((const char *)&observed,
            (const char *)&client_address, client_length)) {
        status = 12;
        goto finish;
    }
    trace_unix_value('h', observed_length);
    raw_close(listener);
    listener = -1;
    if (send(client, "s", 1, 0) != 1 || recv(peer, &byte, 1, 0) != 1 ||
        byte != 's') {
        status = 13;
        goto finish;
    }
    raw_close(peer);
    peer = -1;
    raw_close(client);
    client = -1;
    if (bind(duplicate, (const struct sockaddr *)&listener_address,
            listener_length) != 0) {
        status = 14;
        goto finish;
    }
    trace_unix_value('i', 0);
    errno = 0;
    if (listen(listener, -1) != -1 || errno != EBADF) {
        status = 15;
        goto finish;
    }
    trace_unix_value('j', errno);

finish:
    raw_close(probe);
    raw_close(peer);
    raw_close(client);
    raw_close(duplicate);
    raw_close(listener);
    return status;
}

static int check_unix_named_datagram(void)
{
    struct sockaddr_un receiver_address, sender_address, absent_address;
    struct sockaddr_un observed = { 0 };
    struct sockaddr disconnected = { .sa_family = AF_UNSPEC };
    socklen_t receiver_length = abstract_unix_address(&receiver_address, 'r');
    socklen_t sender_length = abstract_unix_address(&sender_address, 'd');
    socklen_t absent_length = abstract_unix_address(&absent_address, 'x');
    socklen_t observed_length;
    int receiver = -1, sender = -1, duplicate = -1, absent = -1;
    int status = 0;
    char byte = 0;

    receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
    sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    duplicate = socket(AF_UNIX, SOCK_DGRAM, 0);
    absent = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (receiver < 0 || sender < 0 || duplicate < 0 || absent < 0) {
        status = 1;
        goto finish;
    }
    errno = 0;
    if (connect(absent, (const struct sockaddr *)&absent_address,
            absent_length) != -1 || errno != ECONNREFUSED) {
        status = 2;
        goto finish;
    }
    trace_unix_value('k', errno);
    if (bind(receiver, (const struct sockaddr *)&receiver_address,
            receiver_length) != 0 ||
        bind(sender, (const struct sockaddr *)&sender_address,
            sender_length) != 0) {
        status = 3;
        goto finish;
    }
    errno = 0;
    if (listen(receiver, 1) != -1 || errno != EOPNOTSUPP) {
        status = 4;
        goto finish;
    }
    trace_unix_value('l', errno);
    errno = 0;
    if (bind(duplicate, (const struct sockaddr *)&receiver_address,
            receiver_length) != -1 || errno != EADDRINUSE) {
        status = 5;
        goto finish;
    }
    trace_unix_value('m', errno);
    if (connect(sender, (const struct sockaddr *)&receiver_address,
            receiver_length) != 0) {
        status = 6;
        goto finish;
    }
    observed_length = sizeof(observed.sun_family);
    if (getpeername(sender, (struct sockaddr *)&observed,
            &observed_length) != 0 ||
        observed_length != receiver_length || observed.sun_family != AF_UNIX) {
        status = 7;
        goto finish;
    }
    trace_unix_value('n', observed_length);
    if (send(sender, "d", 1, 0) != 1) {
        status = 8;
        goto finish;
    }
    observed_length = sizeof(observed.sun_family);
    if (recvfrom(receiver, &byte, 1, 0, (struct sockaddr *)&observed,
            &observed_length) != 1 || byte != 'd' ||
        observed_length != sender_length || observed.sun_family != AF_UNIX) {
        status = 9;
        goto finish;
    }
    trace_unix_value('o', observed_length);
    if (connect(sender, &disconnected, sizeof(disconnected.sa_family)) != 0) {
        status = 10;
        goto finish;
    }
    errno = 0;
    if (getpeername(sender, (struct sockaddr *)&observed,
            &observed_length) != -1 || errno != ENOTCONN) {
        status = 11;
        goto finish;
    }
    trace_unix_value('p', errno);
    raw_close(receiver);
    receiver = -1;
    if (bind(duplicate, (const struct sockaddr *)&receiver_address,
            receiver_length) != 0) {
        status = 12;
        goto finish;
    }
    trace_unix_value('q', 0);
    errno = 0;
    if (connect(-1, NULL, 1) != -1 || errno != EBADF) {
        status = 13;
        goto finish;
    }
    trace_unix_value('r', errno);

finish:
    raw_close(absent);
    raw_close(duplicate);
    raw_close(sender);
    raw_close(receiver);
    return status;
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

static int check_accept4_zero_flags_dispatch(void)
{
    /* Only accept4 is denied; accept remains available on Linux 5.10+. */
    struct socket_filter_instruction {
        unsigned short code;
        unsigned char true_jump;
        unsigned char false_jump;
        unsigned int value;
    } filter[] = {
        { 0x20, 0, 0, 0 },
        { 0x15, 0, 1, SYS_accept4 },
        { 0x06, 0, 0, 0x00050000U | ENOSYS },
        { 0x06, 0, 0, 0x7fff0000U },
    };
    struct socket_filter_program {
        unsigned short length;
        struct socket_filter_instruction *instructions;
    } program = { 4, filter };
    struct sockaddr_in address = loopback_address();
    socklen_t address_length = sizeof(address);
    int listener = -1;
    int client = -1;
    int peer = -1;
    int status = 0;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 ||
        bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_length) != 0 ||
        listen(listener, 1) != 0 ||
        connect(client, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        status = 1;
        goto finish;
    }
    if (raw_syscall5(SYS_prctl, 38, 1, 0, 0, 0) != 0 ||
        raw_syscall3(SYS_seccomp, 1, 0, (long)&program) != 0) {
        status = 2;
        goto finish;
    }
    if (raw_syscall5(SYS_accept4, -1, 0, 0, 0, 0) != -ENOSYS) {
        status = 3;
        goto finish;
    }
    peer = accept4(listener, NULL, NULL, 0);
    if (peer < 0)
        status = 4;

finish:
    raw_close(peer);
    raw_close(client);
    raw_close(listener);
    return status;
}

int crabc_x86_64_socket_transport_probe(void)
{
    int status;

    status = check_unix_pair();
    if (status != 0)
        return 10 + status;
    status = check_unix_named_stream();
    if (status != 0)
        return 110 + status;
    status = check_unix_named_datagram();
    if (status != 0)
        return 130 + status;
    status = check_loopback_datagram();
    if (status != 0)
        return 30 + status;
    status = check_loopback_stream();
    if (status != 0)
        return 50 + status;
    status = check_error_translation();
    if (status != 0)
        return 70 + status;
    status = check_accept4_zero_flags_dispatch();
    if (status != 0)
        return 90 + status;
    if (raw_syscall3(SYS_write, 1, (long)unix_trace,
            (long)unix_trace_length) != (long)unix_trace_length)
        return 150;
    return 0;
}

#ifndef CRABC_SOCKET_TRANSPORT_FREESTANDING
int main(void)
{
    return crabc_x86_64_socket_transport_probe();
}
#endif
