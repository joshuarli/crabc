/* Loopback TCP state and readiness observations for the static socket leaf.
 * Both peers' address, descriptor flags, empty receive queue, half-close,
 * and errno transitions are checked against the same pinned-musl execution.
 * Raw poll, getsockopt, fcntl, write, and close observe kernel state without
 * selecting additional libc entry points in the freestanding candidate.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>

_Static_assert(SYS_poll == 7 && SYS_write == 1 && SYS_close == 3 &&
    SYS_fcntl == 72 && SYS_getsockopt == 55, "x86 TCP observer syscalls");

static long tcp_raw1(long number, long first)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(first)
        : "rcx", "r11", "memory");
    return result;
}

static long tcp_raw3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static long tcp_raw5(long number, long first, long second, long third,
    long fourth, long fifth)
{
    long result;
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third),
          "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return result;
}

static void tcp_close(int fd)
{
    if (fd >= 0)
        (void)tcp_raw1(SYS_close, fd);
}

static int tcp_flags(int fd, int command)
{
    return (int)tcp_raw3(SYS_fcntl, fd, command, 0);
}

static int tcp_descriptor_state(int fd, int close_on_exec, int nonblocking)
{
    return tcp_flags(fd, F_GETFD) == (close_on_exec ? FD_CLOEXEC : 0) &&
        tcp_flags(fd, F_GETFL) == (O_RDWR | (nonblocking ? O_NONBLOCK : 0));
}

static int tcp_ready(int fd, short events, short required)
{
    struct pollfd entry = { .fd = fd, .events = events };
    long result = tcp_raw3(SYS_poll, (long)&entry, 1, 3000);
    return result == 1 && (entry.revents & required) == required &&
        (entry.revents & POLLNVAL) == 0;
}

static int tcp_error(int fd, int *error)
{
    socklen_t length = sizeof(*error);
    long result = tcp_raw5(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR,
        (long)error, (long)&length);
    return result == 0 && length == sizeof(*error);
}

static struct sockaddr_in tcp_loopback(void)
{
    struct sockaddr_in address = { 0 };
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = 0x0100007fU;
    return address;
}

static char tcp_trace[128];
static size_t tcp_trace_length;

static void tcp_observe(char label, unsigned int value)
{
    static const char digits[] = "0123456789abcdef";
    tcp_trace[tcp_trace_length++] = label;
    tcp_trace[tcp_trace_length++] = ':';
    tcp_trace[tcp_trace_length++] = digits[(value >> 4) & 15];
    tcp_trace[tcp_trace_length++] = digits[value & 15];
    tcp_trace[tcp_trace_length++] = '\n';
}

int crabc_x86_64_socket_tcp_probe(void)
{
    struct sockaddr_in address = tcp_loopback();
    struct sockaddr_in peer_address = { 0 };
    struct sockaddr_in client_address = { 0 };
    socklen_t length = sizeof(address);
    int listener = -1, client = -1, peer = -1;
    int second_client = -1, second_peer = -1, refused = -1, unused = -1;
    int error = -1, status = 0;
    char byte = 0;
    int connected, pending_connect;

    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener < 0 || !tcp_descriptor_state(listener, 1, 1) ||
        bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0 ||
        length != sizeof(address) || address.sin_port == 0 ||
        listen(listener, 2) != 0) {
        status = 1;
        goto finish;
    }
    length = sizeof(peer_address);
    errno = 0;
    if (getpeername(listener, (struct sockaddr *)&peer_address, &length) != -1 ||
        errno != ENOTCONN || length != sizeof(peer_address)) {
        status = 19;
        goto finish;
    }
    tcp_observe('g', (unsigned int)errno);
    if (!tcp_descriptor_state(listener, 1, 1)) {
        status = 20;
        goto finish;
    }
    errno = 0;
    if (accept(listener, NULL, NULL) != -1 || errno != EAGAIN) {
        status = 2;
        goto finish;
    }
    tcp_observe('a', (unsigned int)errno);
    errno = 0;
    if (accept4(listener, NULL, NULL, 0) != -1 || errno != EAGAIN) {
        status = 3;
        goto finish;
    }
    tcp_observe('b', (unsigned int)errno);
    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (client < 0 || !tcp_descriptor_state(client, 1, 1)) {
        status = 4;
        goto finish;
    }
    errno = 0;
    connected = connect(client, (const struct sockaddr *)&address,
        sizeof(address));
    if (connected != 0 && (connected != -1 || errno != EINPROGRESS)) {
        status = 5;
        goto finish;
    }
    pending_connect = connected == -1;
    if (!tcp_ready(client, POLLOUT, POLLOUT) ||
        !tcp_error(client, &error) || error != 0 ||
        !tcp_ready(listener, POLLIN, POLLIN)) {
        status = 6;
        goto finish;
    }
    tcp_observe('c', (unsigned int)error);
    length = sizeof(client_address);
    errno = EDOM;
    if (getsockname(client, (struct sockaddr *)&client_address, &length) != 0 ||
        errno != EDOM || length != sizeof(client_address) ||
        client_address.sin_family != AF_INET ||
        client_address.sin_addr.s_addr != 0x0100007fU ||
        client_address.sin_port == 0) {
        status = 25;
        goto finish;
    }
    tcp_observe('m', (unsigned int)errno);
    length = sizeof(peer_address);
    peer = accept4(listener, (struct sockaddr *)&peer_address, &length,
        SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (peer < 0 || length != sizeof(peer_address) ||
        peer_address.sin_family != AF_INET ||
        peer_address.sin_addr.s_addr != 0x0100007fU ||
        peer_address.sin_port != client_address.sin_port ||
        !tcp_descriptor_state(peer, 1, 1)) {
        status = 7;
        goto finish;
    }
    errno = 0;
    if (recv(peer, &byte, 1, 0) != -1 || errno != EAGAIN ||
        !tcp_descriptor_state(peer, 1, 1)) {
        status = 21;
        goto finish;
    }
    tcp_observe('h', (unsigned int)errno);
    length = sizeof(peer_address);
    errno = EDOM;
    if (getpeername(client, (struct sockaddr *)&peer_address, &length) != 0 ||
        errno != EDOM || length != sizeof(peer_address) ||
        peer_address.sin_family != AF_INET ||
        peer_address.sin_addr.s_addr != 0x0100007fU ||
        peer_address.sin_port != address.sin_port) {
        status = 22;
        goto finish;
    }
    tcp_observe('i', (unsigned int)errno);
    /* A pending connect reports its completion once; a later connect on the
     * same established socket reports EISCONN without changing its flags. */
    errno = 0;
    connected = connect(client, (const struct sockaddr *)&address,
        sizeof(address));
    if (pending_connect) {
        if (connected != 0) {
            status = 18;
            goto finish;
        }
        errno = 0;
        connected = connect(client, (const struct sockaddr *)&address,
            sizeof(address));
    }
    if (connected != -1 || errno != EISCONN ||
        !tcp_descriptor_state(client, 1, 1)) {
        status = 18;
        goto finish;
    }
    tcp_observe('f', (unsigned int)errno);
    if (send(client, "a", 1, 0) != 1 ||
        !tcp_ready(peer, POLLIN, POLLIN) ||
        recv(peer, &byte, 1, 0) != 1 || byte != 'a') {
        status = 8;
        goto finish;
    }
    errno = 0;
    if (recv(peer, &byte, 1, 0) != -1 || errno != EAGAIN ||
        !tcp_descriptor_state(peer, 1, 1)) {
        status = 23;
        goto finish;
    }
    tcp_observe('j', (unsigned int)errno);
    errno = EDOM;
    if (shutdown(client, SHUT_WR) != 0 ||
        errno != EDOM ||
        !tcp_ready(peer, POLLIN, POLLIN) || recv(peer, &byte, 1, 0) != 0 ||
        send(peer, "b", 1, 0) != 1 ||
        !tcp_ready(client, POLLIN, POLLIN) ||
        recv(client, &byte, 1, 0) != 1 || byte != 'b') {
        status = 9;
        goto finish;
    }
    tcp_observe('k', (unsigned int)errno);
    errno = 0;
    if (send(client, "x", 1, MSG_NOSIGNAL) != -1 || errno != EPIPE ||
        !tcp_descriptor_state(client, 1, 1)) {
        status = 24;
        goto finish;
    }
    tcp_observe('l', (unsigned int)errno);
    tcp_close(peer);
    peer = -1;
    if (!tcp_ready(client, POLLIN, POLLIN) || recv(client, &byte, 1, 0) != 0) {
        status = 10;
        goto finish;
    }

    second_client = socket(AF_INET, SOCK_STREAM, 0);
    if (second_client < 0 || connect(second_client,
            (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        !tcp_ready(listener, POLLIN, POLLIN)) {
        status = 11;
        goto finish;
    }
    second_peer = accept(listener, NULL, NULL);
    if (second_peer < 0 || !tcp_descriptor_state(second_peer, 0, 0)) {
        status = 12;
        goto finish;
    }
    tcp_close(second_peer);
    second_peer = -1;
    tcp_close(second_client);
    second_client = -1;
    tcp_close(listener);
    listener = -1;

    /* The closed ephemeral listener reserves a loopback port for a refused
     * nonblocking connection without assuming a fixed host port is free. */
    unused = socket(AF_INET, SOCK_STREAM, 0);
    address = tcp_loopback();
    length = sizeof(address);
    if (unused < 0 || bind(unused, (const struct sockaddr *)&address,
            sizeof(address)) != 0 ||
        getsockname(unused, (struct sockaddr *)&address, &length) != 0 ||
        address.sin_port == 0) {
        status = 13;
        goto finish;
    }
    tcp_close(unused);
    unused = -1;
    refused = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (refused < 0) {
        status = 14;
        goto finish;
    }
    errno = 0;
    connected = connect(refused, (const struct sockaddr *)&address,
        sizeof(address));
    if (connected != -1 || (errno != EINPROGRESS && errno != ECONNREFUSED)) {
        status = 15;
        goto finish;
    }
    if (!tcp_ready(refused, POLLOUT, POLLERR) ||
        !tcp_error(refused, &error) || error != ECONNREFUSED) {
        status = 16;
        goto finish;
    }
    tcp_observe('d', (unsigned int)error);
    if (!tcp_error(refused, &error) || error != 0) {
        status = 16;
        goto finish;
    }
    tcp_observe('e', (unsigned int)error);
    if (tcp_raw3(SYS_write, 1, (long)tcp_trace,
            (long)tcp_trace_length) != (long)tcp_trace_length)
        status = 17;

finish:
    tcp_close(unused);
    tcp_close(refused);
    tcp_close(second_peer);
    tcp_close(second_client);
    tcp_close(peer);
    tcp_close(client);
    tcp_close(listener);
    return status;
}
