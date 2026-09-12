#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "x86_64_workload_protocol.h"
#include "fixtures/diagnostic_marker.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

enum {
    PAYLOAD_BYTES = 4096,
};

static int
parse_port(const char *text, unsigned short *result)
{
    unsigned long value;

    if (!crabc_perf_parse_positive(text, &value) || value > 65535)
        return 0;
    *result = (unsigned short)value;
    return 1;
}

static int
parse_loopback_peer(int family, const char *address_text, const char *port_text,
    struct sockaddr_storage *storage, socklen_t *storage_length)
{
    unsigned short port;

    if (!storage || !storage_length || !parse_port(port_text, &port))
        return 0;
    memset(storage, 0, sizeof *storage);
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)storage;

        address->sin_family = AF_INET;
        address->sin_port = htons(port);
        if (inet_pton(AF_INET, address_text, &address->sin_addr) != 1 ||
            address->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            return 0;
        *storage_length = sizeof *address;
        return 1;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)storage;

        address->sin6_family = AF_INET6;
        address->sin6_port = htons(port);
        if (inet_pton(AF_INET6, address_text, &address->sin6_addr) != 1 ||
            memcmp(&address->sin6_addr, &in6addr_loopback,
                sizeof address->sin6_addr) != 0)
            return 0;
        *storage_length = sizeof *address;
        return 1;
    }
    return 0;
}

static void
make_payload(unsigned char payload[PAYLOAD_BYTES], unsigned long sequence)
{
    size_t index;

    payload[0] = (unsigned char)(sequence >> 24);
    payload[1] = (unsigned char)(sequence >> 16);
    payload[2] = (unsigned char)(sequence >> 8);
    payload[3] = (unsigned char)sequence;
    for (index = 4; index < PAYLOAD_BYTES; index++) {
        payload[index] = (unsigned char)((sequence * 31UL +
            (unsigned long)index * 17UL) & 0xffUL);
    }
}

static int
payload_matches(const unsigned char payload[PAYLOAD_BYTES], unsigned long sequence)
{
    unsigned char expected[PAYLOAD_BYTES];

    make_payload(expected, sequence);
    return memcmp(payload, expected, sizeof expected) == 0;
}

static int
send_all(int descriptor, const unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = send(descriptor, data + offset, length - offset,
            MSG_NOSIGNAL);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return 0;
    }
    return 1;
}

static int
receive_all(int descriptor, unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t received = recv(descriptor, data + offset, length - offset, 0);

        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR)
            continue;
        return 0;
    }
    return 1;
}

static int
run_loopback(int socket_type, int family, unsigned long iterations,
    const char *address_text, const char *port_text,
    const struct crabc_perf_observer *observer)
{
    struct sockaddr_storage peer;
    socklen_t peer_length;
    unsigned char payload[PAYLOAD_BYTES];
    int descriptor = -1;
    unsigned long sequence;
    int valid = 1;

    if (!parse_loopback_peer(family, address_text, port_text, &peer,
            &peer_length))
        return 0;
    descriptor = socket(family, socket_type, 0);
    if (descriptor < 0)
        return 0;
    if (connect(descriptor, (const struct sockaddr *)&peer, peer_length) != 0) {
        valid = 0;
        goto done;
    }
    for (sequence = 0; sequence < iterations; sequence++) {
        make_payload(payload, sequence);
        if (socket_type == SOCK_STREAM) {
            if (!send_all(descriptor, payload, sizeof payload) ||
                !receive_all(descriptor, payload, sizeof payload)) {
                valid = 0;
                break;
            }
        } else {
            ssize_t written;
            ssize_t received;

            do {
                written = send(descriptor, payload, sizeof payload, MSG_NOSIGNAL);
            } while (written < 0 && errno == EINTR);
            if (written != (ssize_t)sizeof payload) {
                valid = 0;
                break;
            }
            do {
                received = recv(descriptor, payload, sizeof payload, 0);
            } while (received < 0 && errno == EINTR);
            if (received != (ssize_t)sizeof payload) {
                valid = 0;
                break;
            }
        }
        if (!payload_matches(payload, sequence)) {
            valid = 0;
            break;
        }
        crabc_perf_consume_uintptr((uintptr_t)sequence);
    }
    /*
     * A successful final echo remains associated with its actual client
     * socket/connection until the observer acknowledges this plateau.
     */
    if (valid && !crabc_perf_observer_reach(observer))
        valid = 0;

done:
    if (descriptor >= 0)
        close(descriptor);
    return valid;
}

static int
parse_ipv4(const char *text, struct in_addr *result)
{
    return text && result && inet_pton(AF_INET, text, result) == 1;
}

static int
parse_ipv6(const char *text, struct in6_addr *result)
{
    return text && result && inet_pton(AF_INET6, text, result) == 1;
}

static int
address_results_match(const struct addrinfo *results, unsigned short port,
    const struct in_addr *expected_ipv4, const struct in6_addr *expected_ipv6,
    int require_ipv4, int require_ipv6)
{
    int seen_ipv4 = 0;
    int seen_ipv6 = 0;
    const struct addrinfo *item;

    for (item = results; item; item = item->ai_next) {
        if (item->ai_family == AF_INET &&
            item->ai_addrlen == sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *address =
                (const struct sockaddr_in *)item->ai_addr;

            if (!require_ipv4 || address->sin_port != htons(port) ||
                memcmp(&address->sin_addr, expected_ipv4,
                    sizeof *expected_ipv4) != 0 || seen_ipv4)
                return 0;
            seen_ipv4 = 1;
        } else if (item->ai_family == AF_INET6 &&
            item->ai_addrlen == sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *address =
                (const struct sockaddr_in6 *)item->ai_addr;

            if (!require_ipv6 || address->sin6_port != htons(port) ||
                memcmp(&address->sin6_addr, expected_ipv6,
                    sizeof *expected_ipv6) != 0 || seen_ipv6)
                return 0;
            seen_ipv6 = 1;
        } else {
            return 0;
        }
    }
    return seen_ipv4 == require_ipv4 && seen_ipv6 == require_ipv6;
}

static int
run_resolver(unsigned long iterations, int requested_family, const char *host,
    const char *service,
    const struct in_addr *expected_ipv4, const struct in6_addr *expected_ipv6,
    int require_ipv4, int require_ipv6,
    const struct crabc_perf_observer *observer)
{
    unsigned short port;
    struct addrinfo hints;
    unsigned long index;

    if (!host || !parse_port(service, &port))
        return 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = requested_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    for (index = 0; index < iterations; index++) {
        struct addrinfo *results = NULL;
        int valid;

        if (getaddrinfo(host, service, &hints, &results) != 0)
            return 0;
        valid = address_results_match(results, port, expected_ipv4, expected_ipv6,
            require_ipv4, require_ipv6);
        /*
         * The final exact address list remains allocated until acknowledgement;
         * prior lookup/free lifetimes retain their ordinary ownership boundary.
         */
        if (valid && index + 1 == iterations &&
            !crabc_perf_observer_reach(observer))
            valid = 0;
        freeaddrinfo(results);
        if (!valid)
            return 0;
    }
    return 1;
}

int
main(int argc, char **argv)
{
    const char *mode;
    unsigned long iterations;
    struct crabc_perf_observer observer;
    int marker_fd;
    int passed = 0;

    if (!crabc_perf_observer_from_environment(&observer))
        return 2;
    if (argc < 3 || !crabc_perf_parse_positive(argv[2], &iterations))
        return 2;
    marker_fd = diagnostic_marker_fd();
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_BEGIN,
            sizeof(DIAGNOSTIC_MARKER_BEGIN) - 1);
    mode = argv[1];
    if (strcmp(mode, "loopback_tcp_ipv4") == 0) {
        if (argc != 5)
            return 2;
        passed = run_loopback(SOCK_STREAM, AF_INET, iterations, argv[3], argv[4],
            &observer);
    } else if (strcmp(mode, "loopback_tcp_ipv6") == 0) {
        if (argc != 5)
            return 2;
        passed = run_loopback(SOCK_STREAM, AF_INET6, iterations, argv[3], argv[4],
            &observer);
    } else if (strcmp(mode, "loopback_udp_ipv4") == 0) {
        if (argc != 5)
            return 2;
        passed = run_loopback(SOCK_DGRAM, AF_INET, iterations, argv[3], argv[4],
            &observer);
    } else if (strcmp(mode, "loopback_udp_ipv6") == 0) {
        if (argc != 5)
            return 2;
        passed = run_loopback(SOCK_DGRAM, AF_INET6, iterations, argv[3], argv[4],
            &observer);
    } else if (strcmp(mode, "resolver_hosts") == 0 ||
        strcmp(mode, "resolver_dns_dual") == 0) {
        struct in_addr expected_ipv4;
        struct in6_addr expected_ipv6;

        if (argc != 7 || !parse_ipv4(argv[5], &expected_ipv4) ||
            !parse_ipv6(argv[6], &expected_ipv6))
            return 2;
        passed = run_resolver(iterations, AF_UNSPEC, argv[3], argv[4], &expected_ipv4,
            &expected_ipv6, 1, 1, &observer);
    } else if (strcmp(mode, "resolver_dns_tcp") == 0) {
        struct in_addr expected_ipv4;

        if (argc != 6 || !parse_ipv4(argv[5], &expected_ipv4))
            return 2;
        passed = run_resolver(iterations, AF_INET, argv[3], argv[4], &expected_ipv4,
            NULL, 1, 0, &observer);
    } else {
        return 2;
    }
    if (!passed)
        return 1;
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_END,
            sizeof(DIAGNOSTIC_MARKER_END) - 1);
    puts("ok");
    return 0;
}
