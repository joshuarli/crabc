/* Pinned-musl/raw Linux/x86-64 socket and address-transport reference. */
#define _GNU_SOURCE 1
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(SYS_ioctl == 16 && SYS_socket == 41 && SYS_connect == 42 &&
                   SYS_accept == 43 && SYS_accept4 == 288,
               "x86 socket syscall numbers");
_Static_assert(SYS_sendto == 44 && SYS_recvfrom == 45 && SYS_sendmsg == 46 &&
                   SYS_recvmsg == 47,
               "x86 transport syscall numbers");
_Static_assert(SYS_shutdown == 48 && SYS_bind == 49 && SYS_listen == 50 &&
                   SYS_getsockname == 51 && SYS_getpeername == 52 &&
                   SYS_socketpair == 53 && SYS_setsockopt == 54 &&
                   SYS_getsockopt == 55,
               "x86 address/socket syscall numbers");
_Static_assert(SYS_recvmmsg == 299 && SYS_sendmmsg == 307,
               "x86 batched-message syscall numbers");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
               "x86 iovec ABI");
_Static_assert(offsetof(struct iovec, iov_base) == 0 &&
                   offsetof(struct iovec, iov_len) == 8,
               "x86 iovec layout");
_Static_assert(sizeof(struct msghdr) == 56 && _Alignof(struct msghdr) == 8,
               "x86 msghdr ABI");
_Static_assert(offsetof(struct msghdr, msg_name) == 0 &&
                   offsetof(struct msghdr, msg_namelen) == 8 &&
                   offsetof(struct msghdr, msg_iov) == 16 &&
                   offsetof(struct msghdr, msg_iovlen) == 24 &&
                   offsetof(struct msghdr, msg_control) == 32 &&
                   offsetof(struct msghdr, msg_controllen) == 40 &&
                   offsetof(struct msghdr, msg_flags) == 48,
               "x86 msghdr layout");
_Static_assert(sizeof(struct mmsghdr) == 64 &&
                   _Alignof(struct mmsghdr) == 8 &&
                   offsetof(struct mmsghdr, msg_hdr) == 0 &&
                   offsetof(struct mmsghdr, msg_len) == 56,
               "x86 mmsghdr layout");
_Static_assert(sizeof(struct sockaddr_in) == 16 &&
                   _Alignof(struct sockaddr_in) == 4 &&
                   offsetof(struct sockaddr_in, sin_family) == 0 &&
                   offsetof(struct sockaddr_in, sin_port) == 2 &&
                   offsetof(struct sockaddr_in, sin_addr) == 4,
               "x86 sockaddr_in layout");
_Static_assert(sizeof(struct sockaddr_in6) == 28 &&
                   _Alignof(struct sockaddr_in6) == 4 &&
                   offsetof(struct sockaddr_in6, sin6_family) == 0 &&
                   offsetof(struct sockaddr_in6, sin6_port) == 2 &&
                   offsetof(struct sockaddr_in6, sin6_flowinfo) == 4 &&
                   offsetof(struct sockaddr_in6, sin6_addr) == 8 &&
                   offsetof(struct sockaddr_in6, sin6_scope_id) == 24,
               "x86 sockaddr_in6 layout");
_Static_assert(sizeof(struct sockaddr_storage) == 128 &&
                   _Alignof(struct sockaddr_storage) == 8,
               "x86 sockaddr_storage layout");

static void die(const char *what) { perror(what); _exit(1); }
static void need(int condition, const char *what) {
    if (!condition) die(what);
}

static int raw_socket(int domain, int type, int protocol) {
    return (int)syscall(SYS_socket, domain, type, protocol);
}
static int raw_ioctl(int fd, unsigned long request, void *argument) {
    return (int)syscall(SYS_ioctl, fd, request, argument);
}
static int raw_socketpair(int domain, int type, int protocol, int sv[2]) {
    return (int)syscall(SYS_socketpair, domain, type, protocol, sv);
}
static int raw_shutdown(int fd, int how) {
    return (int)syscall(SYS_shutdown, fd, how);
}
static int raw_bind(int fd, const struct sockaddr *address, socklen_t length) {
    return (int)syscall(SYS_bind, fd, address, length);
}
static int raw_listen(int fd, int backlog) {
    return (int)syscall(SYS_listen, fd, backlog);
}
static int raw_connect(int fd, const struct sockaddr *address, socklen_t length) {
    return (int)syscall(SYS_connect, fd, address, length);
}
static int raw_accept(int fd, struct sockaddr *address, socklen_t *length) {
    return (int)syscall(SYS_accept, fd, address, length);
}
static int raw_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    return (int)syscall(SYS_accept4, fd, address, length, flags);
}
static int raw_getsockname(int fd, struct sockaddr *address, socklen_t *length) {
    return (int)syscall(SYS_getsockname, fd, address, length);
}
static int raw_getpeername(int fd, struct sockaddr *address, socklen_t *length) {
    return (int)syscall(SYS_getpeername, fd, address, length);
}
static int raw_setsockopt(int fd, int level, int name, const void *value,
                          socklen_t length) {
    return (int)syscall(SYS_setsockopt, fd, level, name, value, length);
}
static int raw_getsockopt(int fd, int level, int name, void *value,
                          socklen_t *length) {
    return (int)syscall(SYS_getsockopt, fd, level, name, value, length);
}
static ssize_t raw_sendto(int fd, const void *buffer, size_t length, int flags,
                          const struct sockaddr *address, socklen_t address_length) {
    return (ssize_t)syscall(SYS_sendto, fd, buffer, length, flags, address,
                            address_length);
}
static ssize_t raw_recvfrom(int fd, void *buffer, size_t length, int flags,
                            struct sockaddr *address, socklen_t *address_length) {
    return (ssize_t)syscall(SYS_recvfrom, fd, buffer, length, flags, address,
                            address_length);
}
static ssize_t raw_sendmsg(int fd, const struct msghdr *message, int flags) {
    return (ssize_t)syscall(SYS_sendmsg, fd, message, flags);
}
static ssize_t raw_recvmsg(int fd, struct msghdr *message, int flags) {
    return (ssize_t)syscall(SYS_recvmsg, fd, message, flags);
}
static int raw_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count,
                        unsigned int flags) {
    return (int)syscall(SYS_sendmmsg, fd, messages, count, flags);
}
static int raw_recvmmsg(int fd, struct mmsghdr *messages, unsigned int count,
                        unsigned int flags, struct timespec *timeout) {
    return (int)syscall(SYS_recvmmsg, fd, messages, count, flags, timeout);
}

static void loopback(struct sockaddr_in *address) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void loopback6(struct sockaddr_in6 *address) {
    memset(address, 0, sizeof(*address));
    address->sin6_family = AF_INET6;
    address->sin6_addr = in6addr_loopback;
}

static void socketpair_case(void) {
    int libc_sv[2], raw_sv[2];
    int libc_at_mark = -1, raw_at_mark = -1;
    char message[] = "socketpair", out[32] = {0};
    need(socketpair(AF_UNIX, SOCK_STREAM, 0, libc_sv) == 0, "socketpair libc");
    need(raw_socketpair(AF_UNIX, SOCK_STREAM, 0, raw_sv) == 0,
         "socketpair raw");
    need(ioctl(libc_sv[1], SIOCATMARK, &libc_at_mark) == 0 && libc_at_mark == 0,
         "socketpair libc at-mark");
    need(raw_ioctl(raw_sv[1], SIOCATMARK, &raw_at_mark) == 0 && raw_at_mark == 0,
         "socketpair raw at-mark");
    need(send(libc_sv[0], message, sizeof(message), 0) == (ssize_t)sizeof(message),
         "socketpair libc send");
    need(raw_recvfrom(libc_sv[1], out, sizeof(out), 0, NULL, NULL) ==
             (ssize_t)sizeof(message) &&
             !strcmp(message, out),
         "socketpair raw receive");
    memset(out, 0, sizeof(out));
    need(raw_sendto(raw_sv[0], message, sizeof(message), 0, NULL, 0) ==
             (ssize_t)sizeof(message),
         "socketpair raw send");
    need(recv(raw_sv[1], out, sizeof(out), 0) == (ssize_t)sizeof(message) &&
             !strcmp(message, out),
         "socketpair libc receive");
    need(shutdown(libc_sv[0], SHUT_WR) == 0 && raw_shutdown(raw_sv[0], SHUT_WR) == 0,
         "socketpair shutdown");
    need(close(libc_sv[0]) == 0 && close(libc_sv[1]) == 0 && close(raw_sv[0]) == 0 &&
             close(raw_sv[1]) == 0,
         "socketpair close");
}

static void socket_flag_case(void) {
    int raw_socket_fd = raw_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int libc_socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

    need(raw_socket_fd >= 0 && libc_socket_fd >= 0, "flagged socket creation");
    need((fcntl(raw_socket_fd, F_GETFD) & FD_CLOEXEC) != 0 &&
             (fcntl(raw_socket_fd, F_GETFL) & O_NONBLOCK) != 0,
         "raw socket creation flags");
    need((fcntl(libc_socket_fd, F_GETFD) & FD_CLOEXEC) != 0 &&
             (fcntl(libc_socket_fd, F_GETFL) & O_NONBLOCK) != 0,
         "libc socket creation flags");
    close(raw_socket_fd);
    close(libc_socket_fd);
}

static void msg_case(void) {
    int libc_sv[2], raw_sv[2];
    char first[] = "msg-one", second[] = "msg-two", out[32] = {0};
    struct iovec send_iov[2] = {{first, 4}, {first + 4, sizeof(first) - 5}};
    struct iovec recv_iov = {out, sizeof(out)};
    struct msghdr send_message = {0}, recv_message = {0};

    need(socketpair(AF_UNIX, SOCK_STREAM, 0, libc_sv) == 0, "msg libc socketpair");
    need(raw_socketpair(AF_UNIX, SOCK_STREAM, 0, raw_sv) == 0,
         "msg raw socketpair");
    send_message.msg_iov = send_iov;
    send_message.msg_iovlen = 2;
    recv_message.msg_iov = &recv_iov;
    recv_message.msg_iovlen = 1;
    need(sendmsg(libc_sv[0], &send_message, 0) == (ssize_t)(sizeof(first) - 1),
         "sendmsg libc");
    need(raw_recvmsg(libc_sv[1], &recv_message, 0) == (ssize_t)(sizeof(first) - 1) &&
             !memcmp(out, first, sizeof(first) - 1),
         "recvmsg raw");

    memset(out, 0, sizeof(out));
    send_iov[0].iov_base = second;
    send_iov[0].iov_len = sizeof(second) - 1;
    send_message.msg_iovlen = 1;
    need(raw_sendmsg(raw_sv[0], &send_message, 0) == (ssize_t)(sizeof(second) - 1),
         "sendmsg raw");
    need(recvmsg(raw_sv[1], &recv_message, 0) == (ssize_t)(sizeof(second) - 1) &&
             !memcmp(out, second, sizeof(second) - 1),
         "recvmsg libc");
    close(libc_sv[0]);
    close(libc_sv[1]);
    close(raw_sv[0]);
    close(raw_sv[1]);
}

static void init_mmessage(struct mmsghdr *message, struct iovec *iov,
                          void *buffer, size_t length) {
    memset(message, 0, sizeof(*message));
    iov->iov_base = buffer;
    iov->iov_len = length;
    message->msg_hdr.msg_iov = iov;
    message->msg_hdr.msg_iovlen = 1;
}

static void mmsg_case(void) {
    int libc_sv[2], raw_sv[2];
    char first[] = "one", second[] = "two";
    char libc_first[8] = {0}, libc_second[8] = {0};
    char raw_first[8] = {0}, raw_second[8] = {0};
    struct iovec libc_send_iov[2], libc_recv_iov[2], raw_send_iov[2], raw_recv_iov[2];
    struct mmsghdr libc_send[2], libc_recv[2], raw_send[2], raw_recv[2];

    need(socketpair(AF_UNIX, SOCK_DGRAM, 0, libc_sv) == 0,
         "mmsg libc socketpair");
    need(raw_socketpair(AF_UNIX, SOCK_DGRAM, 0, raw_sv) == 0,
         "mmsg raw socketpair");
    init_mmessage(&libc_send[0], &libc_send_iov[0], first, sizeof(first) - 1);
    init_mmessage(&libc_send[1], &libc_send_iov[1], second, sizeof(second) - 1);
    init_mmessage(&libc_recv[0], &libc_recv_iov[0], libc_first, sizeof(libc_first));
    init_mmessage(&libc_recv[1], &libc_recv_iov[1], libc_second, sizeof(libc_second));
    need(sendmmsg(libc_sv[0], libc_send, 2, 0) == 2, "sendmmsg libc");
    need(raw_recvmmsg(libc_sv[1], libc_recv, 2, 0, NULL) == 2,
         "recvmmsg raw");
    need(libc_recv[0].msg_len == 3 && libc_recv[1].msg_len == 3 &&
             !memcmp(libc_first, first, 3) && !memcmp(libc_second, second, 3),
         "mmsg raw receive bytes");

    init_mmessage(&raw_send[0], &raw_send_iov[0], first, sizeof(first) - 1);
    init_mmessage(&raw_send[1], &raw_send_iov[1], second, sizeof(second) - 1);
    init_mmessage(&raw_recv[0], &raw_recv_iov[0], raw_first, sizeof(raw_first));
    init_mmessage(&raw_recv[1], &raw_recv_iov[1], raw_second, sizeof(raw_second));
    need(raw_sendmmsg(raw_sv[0], raw_send, 2, 0) == 2, "sendmmsg raw");
    need(recvmmsg(raw_sv[1], raw_recv, 2, 0, NULL) == 2, "recvmmsg libc");
    need(raw_recv[0].msg_len == 3 && raw_recv[1].msg_len == 3 &&
             !memcmp(raw_first, first, 3) && !memcmp(raw_second, second, 3),
         "mmsg libc receive bytes");
    close(libc_sv[0]);
    close(libc_sv[1]);
    close(raw_sv[0]);
    close(raw_sv[1]);
}

static void udp_case(void) {
    int raw_receiver = raw_socket(AF_INET, SOCK_DGRAM, 0);
    int libc_sender = socket(AF_INET, SOCK_DGRAM, 0);
    int libc_receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int raw_sender = raw_socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in raw_address, libc_address, source = {0};
    socklen_t length = sizeof(raw_address);
    char in[] = "udp", out[8] = {0};

    need(raw_receiver >= 0 && libc_sender >= 0 && libc_receiver >= 0 && raw_sender >= 0,
         "udp socket");
    loopback(&raw_address);
    need(raw_bind(raw_receiver, (struct sockaddr *)&raw_address, sizeof(raw_address)) == 0,
         "udp raw bind");
    need(raw_getsockname(raw_receiver, (struct sockaddr *)&raw_address, &length) == 0 &&
             raw_address.sin_port != 0,
         "udp raw getsockname");
    need(sendto(libc_sender, in, sizeof(in), 0, (struct sockaddr *)&raw_address,
                sizeof(raw_address)) == (ssize_t)sizeof(in),
         "udp libc sendto");
    length = sizeof(source);
    need(raw_recvfrom(raw_receiver, out, sizeof(out), 0, (struct sockaddr *)&source,
                      &length) == (ssize_t)sizeof(in) &&
             !memcmp(in, out, sizeof(in)) && source.sin_family == AF_INET,
         "udp raw recvfrom");

    loopback(&libc_address);
    need(bind(libc_receiver, (struct sockaddr *)&libc_address, sizeof(libc_address)) == 0,
         "udp libc bind");
    length = sizeof(libc_address);
    need(getsockname(libc_receiver, (struct sockaddr *)&libc_address, &length) == 0 &&
             libc_address.sin_port != 0,
         "udp libc getsockname");
    memset(out, 0, sizeof(out));
    need(raw_sendto(raw_sender, in, sizeof(in), 0, (struct sockaddr *)&libc_address,
                    sizeof(libc_address)) == (ssize_t)sizeof(in),
         "udp raw sendto");
    length = sizeof(source);
    need(recvfrom(libc_receiver, out, sizeof(out), 0, (struct sockaddr *)&source,
                  &length) == (ssize_t)sizeof(in) &&
             !memcmp(in, out, sizeof(in)),
         "udp libc recvfrom");
    close(raw_receiver);
    close(libc_sender);
    close(libc_receiver);
    close(raw_sender);
}

static void socket_option_case(void) {
    int raw_socket_fd = raw_socket(AF_INET, SOCK_DGRAM, 0);
    int libc_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int option = 1, raw_value = 0, libc_value = 0;
    socklen_t raw_length, libc_length;
    uint64_t raw_first_cookie = 0, raw_second_cookie = 0;
    uint64_t libc_first_cookie = 0, libc_second_cookie = 0;

    need(raw_socket_fd >= 0 && libc_socket_fd >= 0, "socket option sockets");
    need(raw_setsockopt(raw_socket_fd, SOL_SOCKET, SO_REUSEADDR, &option,
                        sizeof(option)) == 0 &&
             setsockopt(libc_socket_fd, SOL_SOCKET, SO_REUSEADDR, &option,
                        sizeof(option)) == 0,
         "socket reuseaddr set");
    raw_length = sizeof(raw_value);
    libc_length = sizeof(libc_value);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_REUSEADDR, &raw_value,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_REUSEADDR, &libc_value,
                        &libc_length) == 0 &&
             raw_length == sizeof(raw_value) && libc_length == sizeof(libc_value) &&
             raw_value != 0 && libc_value != 0,
         "socket reuseaddr query");
    need(raw_setsockopt(raw_socket_fd, SOL_SOCKET, SO_BROADCAST, &option,
                        sizeof(option)) == 0 &&
             setsockopt(libc_socket_fd, SOL_SOCKET, SO_BROADCAST, &option,
                        sizeof(option)) == 0,
         "socket broadcast set");
    raw_value = 0;
    libc_value = 0;
    raw_length = sizeof(raw_value);
    libc_length = sizeof(libc_value);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_BROADCAST, &raw_value,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_BROADCAST, &libc_value,
                        &libc_length) == 0 &&
             raw_value != 0 && libc_value != 0,
         "socket broadcast query");
    raw_length = sizeof(raw_value);
    libc_length = sizeof(libc_value);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_TYPE, &raw_value,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_TYPE, &libc_value,
                        &libc_length) == 0 &&
             raw_value == SOCK_DGRAM && libc_value == SOCK_DGRAM,
         "socket type query");
    raw_length = sizeof(raw_value);
    libc_length = sizeof(libc_value);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_PROTOCOL, &raw_value,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_PROTOCOL, &libc_value,
                        &libc_length) == 0 &&
             raw_value == IPPROTO_UDP && libc_value == IPPROTO_UDP,
         "socket protocol query");
    raw_length = sizeof(raw_value);
    libc_length = sizeof(libc_value);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_DOMAIN, &raw_value,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_DOMAIN, &libc_value,
                        &libc_length) == 0 &&
             raw_value == AF_INET && libc_value == AF_INET,
         "socket domain query");
    raw_length = sizeof(raw_first_cookie);
    libc_length = sizeof(libc_first_cookie);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_COOKIE, &raw_first_cookie,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_COOKIE, &libc_first_cookie,
                        &libc_length) == 0 &&
             raw_length == sizeof(raw_first_cookie) &&
             libc_length == sizeof(libc_first_cookie) && raw_first_cookie != 0 &&
             libc_first_cookie != 0,
         "socket cookie query");
    raw_length = sizeof(raw_second_cookie);
    libc_length = sizeof(libc_second_cookie);
    need(raw_getsockopt(raw_socket_fd, SOL_SOCKET, SO_COOKIE, &raw_second_cookie,
                        &raw_length) == 0 &&
             getsockopt(libc_socket_fd, SOL_SOCKET, SO_COOKIE, &libc_second_cookie,
                        &libc_length) == 0 &&
             raw_second_cookie == raw_first_cookie &&
             libc_second_cookie == libc_first_cookie,
         "socket cookie stability");
    close(raw_socket_fd);
    close(libc_socket_fd);
}

static void ipv6_case(void) {
    int raw_receiver = raw_socket(AF_INET6, SOCK_DGRAM, 0);
    int libc_sender = socket(AF_INET6, SOCK_DGRAM, 0);
    int libc_receiver = socket(AF_INET6, SOCK_DGRAM, 0);
    int raw_sender = raw_socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 raw_address, libc_address, source = {0};
    socklen_t length = sizeof(raw_address);
    char in[] = "ipv6", out[8] = {0};

    need(raw_receiver >= 0 && libc_sender >= 0 && libc_receiver >= 0 && raw_sender >= 0,
         "ipv6 socket");
    loopback6(&raw_address);
    need(raw_bind(raw_receiver, (struct sockaddr *)&raw_address, sizeof(raw_address)) == 0,
         "ipv6 raw bind");
    need(raw_getsockname(raw_receiver, (struct sockaddr *)&raw_address, &length) == 0 &&
             raw_address.sin6_port != 0,
         "ipv6 raw getsockname");
    need(sendto(libc_sender, in, sizeof(in), 0, (struct sockaddr *)&raw_address,
                sizeof(raw_address)) == (ssize_t)sizeof(in),
         "ipv6 libc sendto");
    length = sizeof(source);
    need(raw_recvfrom(raw_receiver, out, sizeof(out), 0, (struct sockaddr *)&source,
                      &length) == (ssize_t)sizeof(in) &&
             !memcmp(in, out, sizeof(in)) && source.sin6_family == AF_INET6,
         "ipv6 raw recvfrom");

    loopback6(&libc_address);
    need(bind(libc_receiver, (struct sockaddr *)&libc_address, sizeof(libc_address)) == 0,
         "ipv6 libc bind");
    length = sizeof(libc_address);
    need(getsockname(libc_receiver, (struct sockaddr *)&libc_address, &length) == 0 &&
             libc_address.sin6_port != 0,
         "ipv6 libc getsockname");
    memset(out, 0, sizeof(out));
    need(raw_sendto(raw_sender, in, sizeof(in), 0, (struct sockaddr *)&libc_address,
                    sizeof(libc_address)) == (ssize_t)sizeof(in),
         "ipv6 raw sendto");
    length = sizeof(source);
    need(recvfrom(libc_receiver, out, sizeof(out), 0, (struct sockaddr *)&source,
                  &length) == (ssize_t)sizeof(in) && !memcmp(in, out, sizeof(in)) &&
             source.sin6_family == AF_INET6,
         "ipv6 libc recvfrom");
    close(raw_receiver);
    close(libc_sender);
    close(libc_receiver);
    close(raw_sender);
}

static void tcp_case(void) {
    int listener = raw_socket(AF_INET, SOCK_STREAM, 0);
    int libc_client = socket(AF_INET, SOCK_STREAM, 0);
    int raw_client = raw_socket(AF_INET, SOCK_STREAM, 0);
    int libc_client2 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address, peer = {0};
    socklen_t length = sizeof(address);
    int one = 1, value = -1;
    char out[8] = {0};

    need(listener >= 0 && libc_client >= 0 && raw_client >= 0 && libc_client2 >= 0,
         "tcp socket");
    loopback(&address);
    need(raw_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0,
         "tcp raw reuseaddr");
    need(raw_setsockopt(listener, SOL_SOCKET, SO_OOBINLINE, &one, sizeof(one)) == 0,
         "tcp raw oobinline");
    need(setsockopt(libc_client, SOL_SOCKET, SO_OOBINLINE, &one, sizeof(one)) == 0,
         "tcp libc oobinline");
    length = sizeof(value);
    need(raw_getsockopt(listener, SOL_SOCKET, SO_OOBINLINE, &value, &length) == 0 &&
             value != 0,
         "tcp raw oobinline query");
    value = -1;
    length = sizeof(value);
    need(getsockopt(libc_client, SOL_SOCKET, SO_OOBINLINE, &value, &length) == 0 &&
             value != 0,
         "tcp libc oobinline query");
    length = sizeof(value);
    need(raw_getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 &&
             value == 0,
         "tcp raw pre-listen state");
    value = -1;
    length = sizeof(value);
    need(getsockopt(libc_client, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 &&
             value == 0,
         "tcp libc pre-listen state");
    need(raw_bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0,
         "tcp raw bind");
    length = sizeof(address);
    need(raw_getsockname(listener, (struct sockaddr *)&address, &length) == 0 &&
             address.sin_port != 0,
         "tcp raw getsockname");
    need(raw_listen(listener, 2) == 0, "tcp raw listen");
    value = 0;
    length = sizeof(value);
    need(raw_getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 &&
             value != 0,
         "tcp raw listening state");
    need(connect(libc_client, (struct sockaddr *)&address, sizeof(address)) == 0,
         "tcp libc connect");
    length = sizeof(peer);
    int accepted = raw_accept4(listener, (struct sockaddr *)&peer, &length,
                               SOCK_CLOEXEC | SOCK_NONBLOCK);
    need(accepted >= 0 && peer.sin_family == AF_INET, "tcp raw accept4");
    need((fcntl(accepted, F_GETFD) & FD_CLOEXEC) != 0 &&
             (fcntl(accepted, F_GETFL) & O_NONBLOCK) != 0,
         "tcp accept4 flags");
    length = sizeof(peer);
    need(raw_getpeername(accepted, (struct sockaddr *)&peer, &length) == 0 &&
             peer.sin_family == AF_INET,
         "tcp raw getpeername");
    need(send(libc_client, "ok", 2, 0) == 2, "tcp libc send");
    need(raw_recvfrom(accepted, out, sizeof(out), 0, NULL, NULL) == 2 &&
             !memcmp(out, "ok", 2),
         "tcp raw receive");

    need(raw_connect(raw_client, (struct sockaddr *)&address, sizeof(address)) == 0,
         "tcp raw connect");
    int raw_accepted = raw_accept(listener, NULL, NULL);
    need(raw_accepted >= 0, "tcp raw accept");
    need(raw_sendto(raw_client, "go", 2, 0, NULL, 0) == 2, "tcp raw send");
    memset(out, 0, sizeof(out));
    need(raw_recvfrom(raw_accepted, out, sizeof(out), 0, NULL, NULL) == 2 &&
             !memcmp(out, "go", 2),
         "tcp raw receive");
    need(raw_shutdown(raw_client, SHUT_WR) == 0, "tcp raw shutdown");

    need(connect(libc_client2, (struct sockaddr *)&address, sizeof(address)) == 0,
         "tcp libc second connect");
    int libc_accepted = accept(listener, NULL, NULL);
    need(libc_accepted >= 0, "tcp libc accept");
    need(send(libc_client2, "hi", 2, 0) == 2, "tcp libc second send");
    memset(out, 0, sizeof(out));
    need(recv(libc_accepted, out, sizeof(out), 0) == 2 && !memcmp(out, "hi", 2),
         "tcp libc receive");
    close(libc_accepted);
    close(raw_accepted);
    close(accepted);
    close(raw_client);
    close(libc_client);
    close(libc_client2);
    close(listener);
}

static void error_case(void) {
    int raw_error_socket, libc_error_socket;
    socklen_t zero = 0;

    errno = 0;
    need(raw_socket(AF_INET, -1, 0) == -1 && errno == EINVAL,
         "raw invalid socket error");
    errno = 0;
    need(socket(AF_INET, -1, 0) == -1 && errno == EINVAL,
         "libc invalid socket error");
    raw_error_socket = raw_socket(AF_UNIX, SOCK_STREAM, 0);
    libc_error_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    need(raw_error_socket >= 0 && libc_error_socket >= 0, "error sockets");
    errno = 0;
    need(raw_setsockopt(raw_error_socket, 0x7fff, 1, NULL, 0) == -1 &&
             (errno == ENOPROTOOPT || errno == EOPNOTSUPP),
         "raw invalid option error");
    errno = 0;
    need(setsockopt(libc_error_socket, 0x7fff, 1, NULL, 0) == -1 &&
             (errno == ENOPROTOOPT || errno == EOPNOTSUPP),
         "libc invalid option error");
    close(raw_error_socket);
    close(libc_error_socket);
    errno = 0;
    need(raw_getsockname(-1, NULL, &zero) == -1 && errno == EBADF,
         "raw closed socket error");
    errno = 0;
    need(getsockname(-1, NULL, &zero) == -1 && errno == EBADF,
         "libc closed socket error");
}

int main(void) {
    socketpair_case();
    socket_flag_case();
    msg_case();
    mmsg_case();
    udp_case();
    socket_option_case();
    ipv6_case();
    tcp_case();
    error_case();
    puts("syscalls=ioctl:16,socket:41,socketpair:53,bind:49,listen:50,connect:42,accept:43,accept4:288,getsockname:51,getpeername:52,shutdown:48,setsockopt:54,sendto:44,recvfrom:45,sendmsg:46,recvmsg:47,recvmmsg:299,sendmmsg:307 abi=iovec16:msghdr56:mmsghdr64:sockaddr_in16:sockaddr_in6-28:storage128 libc-raw=socketpair:udp:ipv6:tcp:options:msg:mmsg errors=EINVAL:invalid-type,ENOPROTOOPT-or-EOPNOTSUPP:invalid-level,EBADF:closed-fd c-api-selection=excluded");
    return 0;
}
