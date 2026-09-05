/* Ordinary installed Linux/x86-64 local IPC/readiness consumer.
 *
 * The caller supplies no network authority: this program creates one private
 * AF_UNIX socketpair and one AF_INET listener bound only to 127.0.0.1:0. It
 * uses ordinary installed C interfaces to combine selected descriptor close,
 * socket transport/messages, scatter/gather I/O, poll, epoll, and selected
 * pthread lifecycle providers. Every owner closes its endpoint on both normal
 * and error paths. The direct syscall leaves deliberately do not make their
 * blocking calls pthread cancellation points; each wait has an explicit,
 * bounded readiness timeout instead.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

enum {
    READINESS_TIMEOUT_MS = 1000,
    QUIESCENT_TIMEOUT_MS = 25,
};

_Static_assert(sizeof(socklen_t) == 4 && sizeof(ssize_t) == 8,
    "x86 socket scalar ABI");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 scatter/gather ABI");
_Static_assert(sizeof(struct epoll_event) == 12 && _Alignof(struct epoll_event) == 1,
    "x86 packed epoll ABI");

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = left;
    const unsigned char *right_bytes = right;
    size_t index;

    for (index = 0; index != length; ++index)
        if (left_bytes[index] != right_bytes[index])
            return 0;
    return 1;
}

static void close_owned(int *descriptor)
{
    if (*descriptor >= 0) {
        (void)close(*descriptor);
        *descriptor = -1;
    }
}

static int wait_for_events(int descriptor, short requested, int timeout,
    short *observed)
{
    struct pollfd event = {
        .fd = descriptor,
        .events = requested,
        .revents = 0,
    };
    int result = poll(&event, 1, timeout);

    if (result < 0)
        return -1;
    if (observed != 0)
        *observed = event.revents;
    return result;
}

struct unix_round {
    int endpoint;
    volatile int result;
};

static void *unix_peer(void *opaque)
{
    static const char expected[] = "unix-ping";
    static const char response_first[] = "unix";
    static const char response_second[] = "-pong";
    struct unix_round *round = opaque;
    char first[4] = { 0 };
    char second[sizeof(expected) - sizeof(first)] = { 0 };
    struct iovec input[2] = {
        { first, sizeof(first) },
        { second, sizeof(second) },
    };
    struct iovec output[2] = {
        { (void *)response_first, sizeof(response_first) - 1 },
        { (void *)response_second, sizeof(response_second) - 1 },
    };
    short observed = 0;

    if (wait_for_events(round->endpoint, POLLIN, READINESS_TIMEOUT_MS,
            &observed) != 1 || !(observed & POLLIN))
        round->result = 1;
    else if (readv(round->endpoint, input, 2) != sizeof(expected) - 1 ||
        !bytes_equal(first, expected, sizeof(first)) ||
        !bytes_equal(second, expected + sizeof(first), sizeof(second)))
        round->result = 2;
    else if (recv(round->endpoint, first, sizeof(first), 0) != 0)
        round->result = 3;
    else if (writev(round->endpoint, output, 2) !=
        (ssize_t)(sizeof(response_first) + sizeof(response_second) - 2))
        round->result = 4;
    else if (shutdown(round->endpoint, SHUT_WR) != 0)
        round->result = 5;
    else
        round->result = 0;

    close_owned(&round->endpoint);
    return 0;
}

static int check_unix_socketpair(void)
{
    static const char request_first[] = "unix";
    static const char request_second[] = "-ping";
    static const char expected_response[] = "unix-pong";
    char response_first[4] = { 0 };
    char response_second[sizeof(expected_response) - sizeof(response_first)] = { 0 };
    char discarded = 0;
    struct iovec request[2] = {
        { (void *)request_first, sizeof(request_first) - 1 },
        { (void *)request_second, sizeof(request_second) - 1 },
    };
    struct iovec response[2] = {
        { response_first, sizeof(response_first) },
        { response_second, sizeof(response_second) },
    };
    struct epoll_event registration = {
        .events = EPOLLIN | EPOLLRDHUP,
        .data = { .fd = -1 },
    };
    struct epoll_event event = { 0 };
    struct unix_round round = {
        .endpoint = -1,
        .result = -1,
    };
    pthread_t peer;
    int peer_created = 0;
    int pair[2] = { -1, -1 };
    int readiness = -1;
    int epoll_descriptor = -1;
    short observed = 0;
    int status = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        status = 1;
        goto finish;
    }
    epoll_descriptor = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_descriptor < 0) {
        status = 2;
        goto finish;
    }
    registration.data.fd = pair[0];
    if (epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, pair[0], &registration) != 0) {
        status = 3;
        goto finish;
    }
    if (wait_for_events(pair[0], POLLIN, QUIESCENT_TIMEOUT_MS, &observed) != 0 ||
        observed != 0 || epoll_wait(epoll_descriptor, &event, 1, 0) != 0) {
        status = 4;
        goto finish;
    }
    round.endpoint = pair[1];
    if (pthread_create(&peer, 0, unix_peer, &round) != 0) {
        status = 5;
        goto finish;
    }
    peer_created = 1;
    pair[1] = -1;
    if (writev(pair[0], request, 2) !=
        (ssize_t)(sizeof(request_first) + sizeof(request_second) - 2) ||
        shutdown(pair[0], SHUT_WR) != 0) {
        status = 6;
        goto finish;
    }
    readiness = epoll_wait(epoll_descriptor, &event, 1, READINESS_TIMEOUT_MS);
    if (readiness != 1 || !(event.events & EPOLLIN) || event.data.fd != pair[0]) {
        status = 7;
        goto finish;
    }
    if (readv(pair[0], response, 2) != sizeof(expected_response) - 1 ||
        !bytes_equal(response_first, expected_response, sizeof(response_first)) ||
        !bytes_equal(response_second, expected_response + sizeof(response_first),
            sizeof(response_second))) {
        status = 8;
        goto finish;
    }
    if (recv(pair[0], &discarded, sizeof(discarded), 0) != 0) {
        status = 9;
        goto finish;
    }
    if (wait_for_events(pair[0], POLLIN, 0, &observed) != 1 ||
        !(observed & (POLLIN | POLLHUP | POLLRDHUP))) {
        status = 10;
        goto finish;
    }
    errno = 0;
    if (send(pair[0], "x", 1, MSG_NOSIGNAL) != -1 || errno != EPIPE) {
        status = 11;
        goto finish;
    }

finish:
    close_owned(&epoll_descriptor);
    close_owned(&pair[0]);
    close_owned(&pair[1]);
    if (peer_created && pthread_join(peer, 0) != 0 && status == 0)
        status = 12;
    if (peer_created && round.result != 0 && status == 0)
        status = 13;
    return status;
}

struct loopback_round {
    struct sockaddr_in address;
    volatile int result;
};

static void *loopback_client(void *opaque)
{
    static const char request_first[] = "loop";
    static const char request_second[] = "-ping";
    static const char expected_response[] = "loop-pong";
    struct loopback_round *round = opaque;
    char response_first[4] = { 0 };
    char response_second[sizeof(expected_response) - sizeof(response_first)] = { 0 };
    char discarded = 0;
    struct iovec request_iov[2] = {
        { (void *)request_first, sizeof(request_first) - 1 },
        { (void *)request_second, sizeof(request_second) - 1 },
    };
    struct msghdr request = {
        .msg_iov = request_iov,
        .msg_iovlen = 2,
    };
    struct iovec response_iov[2] = {
        { response_first, sizeof(response_first) },
        { response_second, sizeof(response_second) },
    };
    struct msghdr response = {
        .msg_iov = response_iov,
        .msg_iovlen = 2,
    };
    int endpoint = -1;
    short observed = 0;

    endpoint = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (endpoint < 0)
        round->result = 1;
    else if (connect(endpoint, (const struct sockaddr *)(const void *)&round->address,
            sizeof(round->address)) != 0)
        round->result = 2;
    else if (sendmsg(endpoint, &request, 0) != 9 || shutdown(endpoint, SHUT_WR) != 0)
        round->result = 3;
    else if (wait_for_events(endpoint, POLLIN, READINESS_TIMEOUT_MS, &observed) != 1 ||
        !(observed & POLLIN))
        round->result = 4;
    else if (recvmsg(endpoint, &response, 0) != 9 ||
        !bytes_equal(response_first, expected_response, sizeof(response_first)) ||
        !bytes_equal(response_second, expected_response + sizeof(response_first),
            sizeof(response_second)))
        round->result = 5;
    else if (recv(endpoint, &discarded, sizeof(discarded), 0) != 0)
        round->result = 6;
    else
        round->result = 0;

    close_owned(&endpoint);
    return 0;
}

static int check_loopback_stream(void)
{
    static const char expected_request[] = "loop-ping";
    static const char response_first[] = "loop";
    static const char response_second[] = "-pong";
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr = { .s_addr = 0 },
    };
    struct loopback_round round = {
        .address = { 0 },
        .result = -1,
    };
    char request_first[4] = { 0 };
    char request_second[sizeof(expected_request) - sizeof(request_first)] = { 0 };
    char discarded = 0;
    struct iovec request_iov[2] = {
        { request_first, sizeof(request_first) },
        { request_second, sizeof(request_second) },
    };
    struct msghdr request = {
        .msg_iov = request_iov,
        .msg_iovlen = 2,
    };
    struct iovec response_iov[2] = {
        { (void *)response_first, sizeof(response_first) - 1 },
        { (void *)response_second, sizeof(response_second) - 1 },
    };
    socklen_t address_length = sizeof(address);
    pthread_t client;
    int client_created = 0;
    int listener = -1;
    int accepted = -1;
    short observed = 0;
    int status = 0;

    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || bind(listener, (const struct sockaddr *)(const void *)&address,
            sizeof(address)) != 0 || listen(listener, 1) != 0) {
        status = 1;
        goto finish;
    }
    if (getsockname(listener, (struct sockaddr *)(void *)&address, &address_length) != 0 ||
        address_length != sizeof(address) || address.sin_family != AF_INET ||
        address.sin_port == 0 || address.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        status = 2;
        goto finish;
    }
    round.address = address;
    if (pthread_create(&client, 0, loopback_client, &round) != 0) {
        status = 3;
        goto finish;
    }
    client_created = 1;
    if (wait_for_events(listener, POLLIN, READINESS_TIMEOUT_MS, &observed) != 1 ||
        !(observed & POLLIN)) {
        status = 4;
        goto finish;
    }
    accepted = accept4(listener, 0, 0, SOCK_CLOEXEC);
    if (accepted < 0) {
        status = 5;
        goto finish;
    }
    if (recvmsg(accepted, &request, 0) != sizeof(expected_request) - 1 ||
        !bytes_equal(request_first, expected_request, sizeof(request_first)) ||
        !bytes_equal(request_second, expected_request + sizeof(request_first),
            sizeof(request_second))) {
        status = 6;
        goto finish;
    }
    if (recv(accepted, &discarded, sizeof(discarded), 0) != 0 ||
        writev(accepted, response_iov, 2) != 9 || shutdown(accepted, SHUT_WR) != 0) {
        status = 7;
        goto finish;
    }
    errno = 0;
    if (accept4(-1, 0, 0, SOCK_CLOEXEC) != -1 || errno != EBADF) {
        status = 8;
        goto finish;
    }

finish:
    close_owned(&accepted);
    close_owned(&listener);
    if (client_created && pthread_join(client, 0) != 0 && status == 0)
        status = 9;
    if (client_created && round.result != 0 && status == 0)
        status = 10;
    return status;
}

int main(void)
{
    int result = check_unix_socketpair();

    if (result != 0)
        return 64 + result;
    result = check_loopback_stream();
    if (result != 0)
        return 96 + result;
    return 0;
}
