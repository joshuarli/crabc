/*
 * Deterministic resolver/network workload.
 *
 * This source is compiled once with the pinned musl headers and linked twice:
 * once to musl and once to crabc.  Resolver state is installed through the
 * public res_state ABI. The runner also supplies a private, isolated
 * /etc/resolv.conf because legacy musl res_query may reload its internal
 * state from that file.
 */
/* musl hides the historical h_errno/status names under strict C11 unless a
   feature profile requests the resolver extensions.  Keep this before every
   pinned-musl header so the compile-once object sees the public ABI used below. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* glibc's nameser.h hides the historical aliases unless compatibility
   headers are enabled; musl exposes them publicly.  Keep this fixture
   source-compatible with both header sets without changing its ABI use. */
#ifndef C_IN
#define C_IN 1
#endif
#ifndef T_A
#define T_A 1
#endif
#ifndef T_AAAA
#define T_AAAA 28
#endif
#ifndef T_CNAME
#define T_CNAME 5
#endif

static int fail(const char *case_name)
{
    fprintf(stderr, "resolver-network: %s\n", case_name);
    return 1;
}

static unsigned short query_u16(const unsigned char *p)
{
    return (unsigned short)(((unsigned short)p[0] << 8) | p[1]);
}

static int skip_dns_name(const unsigned char *packet, int length, int offset)
{
    int labels = 0;
    while (offset < length && labels++ < 128) {
        unsigned char size = packet[offset++];
        if (size == 0)
            return offset;
        if ((size & 0xc0) == 0xc0)
            return offset + 1 <= length ? offset + 1 : -1;
        if (size > 63 || offset + size > length)
            return -1;
        offset += size;
    }
    return -1;
}

static int find_dns_answer(const unsigned char *packet, int length, int qtype,
    unsigned char *value, int value_length)
{
    unsigned short questions;
    unsigned short answers;
    int offset = 12;
    int index;

    if (length < 12)
        return 0;
    questions = query_u16(packet + 4);
    answers = query_u16(packet + 6);
    for (index = 0; index < questions; index++) {
        offset = skip_dns_name(packet, length, offset);
        if (offset < 0 || offset + 4 > length)
            return 0;
        offset += 4;
    }
    for (index = 0; index < answers; index++) {
        unsigned short type;
        unsigned short class_code;
        unsigned short data_length;

        offset = skip_dns_name(packet, length, offset);
        if (offset < 0 || offset + 10 > length)
            return 0;
        type = query_u16(packet + offset);
        class_code = query_u16(packet + offset + 2);
        data_length = query_u16(packet + offset + 8);
        offset += 10;
        if (offset + data_length > length)
            return 0;
        if (type == (unsigned short)qtype && class_code == C_IN &&
            data_length == (unsigned short)value_length) {
            memcpy(value, packet + offset, (size_t)value_length);
            return 1;
        }
        offset += data_length;
    }
    return 0;
}

static int find_dns_cname(const unsigned char *packet, int length,
    const char *expected)
{
    unsigned short questions;
    unsigned short answers;
    int offset = 12;
    int index;

    if (length < 12 || !expected)
        return 0;
    questions = query_u16(packet + 4);
    answers = query_u16(packet + 6);
    for (index = 0; index < questions; index++) {
        offset = skip_dns_name(packet, length, offset);
        if (offset < 0 || offset + 4 > length)
            return 0;
        offset += 4;
    }
    for (index = 0; index < answers; index++) {
        unsigned short type;
        unsigned short class_code;
        unsigned short data_length;

        offset = skip_dns_name(packet, length, offset);
        if (offset < 0 || offset + 10 > length)
            return 0;
        type = query_u16(packet + offset);
        class_code = query_u16(packet + offset + 2);
        data_length = query_u16(packet + offset + 8);
        offset += 10;
        if (offset + data_length > length)
            return 0;
        if (type == T_CNAME && class_code == C_IN) {
            char target[256];
            int expanded = dn_expand(packet, packet + length, packet + offset,
                target, sizeof target);
            if (expanded >= 0 && strcmp(target, expected) == 0)
                return 1;
        }
        offset += data_length;
    }
    return 0;
}

static int install_nameservers(int search_domain)
{
    static char search_name[] = "search.test";
    static const char *nameservers[] = {
        "127.0.0.1", "127.0.0.2", "127.0.0.3"
    };
    res_state state;
    int index;

    /* res_init establishes the public state ABI.  All nameservers and search
       settings used by this workload are then overwritten below. */
    if (res_init() != 0)
        return 0;
    state = __res_state();
    if (!state)
        return 0;
    memset(state->nsaddr_list, 0, sizeof state->nsaddr_list);
    /* res_init may have discovered IPv6 nameservers from the host file.  The
       harness is intentionally loopback-only, so clear the public extension
       before installing our deterministic IPv4 list. */
    memset(&state->_u, 0, sizeof state->_u);
    for (index = 0; index < 3 && index < MAXNS; index++) {
        state->nsaddr_list[index].sin_family = AF_INET;
        state->nsaddr_list[index].sin_port = htons(53);
        if (inet_pton(AF_INET, nameservers[index],
                &state->nsaddr_list[index].sin_addr) != 1)
            return 0;
    }
    state->nscount = 3 < MAXNS ? 3 : MAXNS;
    state->retrans = 1;
    state->retry = 1;
    state->options = RES_INIT | RES_RECURSE;
    state->ndots = 1;
    memset(state->dnsrch, 0, sizeof state->dnsrch);
    if (search_domain) {
        state->options |= RES_DEFNAMES | RES_DNSRCH;
        state->dnsrch[0] = search_name;
        state->defdname[0] = 's';
        state->defdname[1] = 'e';
        state->defdname[2] = 'a';
        state->defdname[3] = 'r';
        state->defdname[4] = 'c';
        state->defdname[5] = 'h';
        state->defdname[6] = '.';
        state->defdname[7] = 't';
        state->defdname[8] = 'e';
        state->defdname[9] = 's';
        state->defdname[10] = 't';
        state->defdname[11] = '\0';
    }
    return 1;
}

static int query_a(const char *name, const char *expected)
{
    unsigned char packet[2048];
    unsigned char value[4];
    struct in_addr address;
    int length;

    length = res_query(name, C_IN, T_A, packet, sizeof packet);
    if (length < 0 || !find_dns_answer(packet, length, T_A, value, 4))
        return 0;
    if (inet_pton(AF_INET, expected, &address) != 1)
        return 0;
    return memcmp(value, &address, 4) == 0;
}

/* musl preserves the historical res_search alias-to-res_query ABI, so DNS
   search-list behavior belongs to the standards-facing getaddrinfo path.
   This verifies the resolver configuration rather than treating a legacy
   extension as a search implementation. */
static int search_a(const char *name, const char *expected)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry;
    struct in_addr address;
    int found = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    if (getaddrinfo(name, NULL, &hints, &results) != 0)
        return 0;
    if (inet_pton(AF_INET, expected, &address) != 1)
        goto out;
    for (entry = results; entry; entry = entry->ai_next) {
        struct sockaddr_in *result_address;

        if (entry->ai_family != AF_INET ||
            entry->ai_addrlen < sizeof(struct sockaddr_in))
            continue;
        result_address = (struct sockaddr_in *)entry->ai_addr;
        if (memcmp(&result_address->sin_addr, &address,
                sizeof address) == 0) {
            found = 1;
            break;
        }
    }
out:
    freeaddrinfo(results);
    return found;
}

static int query_aaaa(const char *name, const char *expected)
{
    unsigned char packet[2048];
    unsigned char value[16];
    struct in6_addr address;
    int length;

    length = res_query(name, C_IN, T_AAAA, packet, sizeof packet);
    if (length < 0 || !find_dns_answer(packet, length, T_AAAA, value, 16))
        return 0;
    if (inet_pton(AF_INET6, expected, &address) != 1)
        return 0;
    return memcmp(value, &address, 16) == 0;
}

static int query_cname(const char *name, const char *expected_name,
    const char *expected_address)
{
    unsigned char packet[2048];
    unsigned char value[4];
    struct in_addr address;
    int length;

    length = res_query(name, C_IN, T_A, packet, sizeof packet);
    if (length < 0 || !find_dns_cname(packet, length, expected_name) ||
        !find_dns_answer(packet, length, T_A, value, 4) ||
        inet_pton(AF_INET, expected_address, &address) != 1)
        return 0;
    return memcmp(value, &address, 4) == 0;
}

static int resolver_cases(void)
{
    unsigned char packet[2048];

    if (!install_nameservers(0) ||
        !query_a("a.example.test", "198.51.100.42"))
        return fail("resolver-a");
    puts("resolver.a=198.51.100.42");

    if (!install_nameservers(0) ||
        !query_aaaa("aaaa.example.test", "2001:db8::42"))
        return fail("resolver-aaaa");
    puts("resolver.aaaa=2001:db8::42");

    if (!install_nameservers(0) ||
        res_query("nxdomain.example.test", C_IN, T_A, packet,
            sizeof packet) != -1 || h_errno != HOST_NOT_FOUND)
        return fail("resolver-nxdomain");
    puts("resolver.nxdomain=HOST_NOT_FOUND");

    if (!install_nameservers(0) ||
        res_query("nodata.example.test", C_IN, T_A, packet,
            sizeof packet) != -1 ||
        (h_errno != NO_DATA && h_errno != NO_ADDRESS))
        return fail("resolver-nodata");
    puts("resolver.nodata=NO_DATA");

    if (!install_nameservers(0) ||
        !query_a("malformed.example.test", "198.51.100.43"))
        return fail("resolver-malformed-wrong-id");
    puts("resolver.malformed-wrong-id=accepted-valid");

    if (!install_nameservers(0) ||
        !query_cname("alias.example.test", "target.example.test",
            "198.51.100.44"))
        return fail("resolver-cname");
    puts("resolver.cname=target.example.test");

    if (!install_nameservers(0) ||
        !query_a("tc.example.test", "198.51.100.45"))
        return fail("resolver-tc-tcp");
    puts("resolver.tc-tcp=accepted-over-tcp");

    if (!install_nameservers(1) ||
        !search_a("searchhost", "198.51.100.17"))
        return fail("resolver-search");
    puts("resolver.search=searchhost.search.test");

    /* The valid endpoint intentionally drops this name, then the configured
       drop endpoint drops it too. The third endpoint answers. retrans/retry
       are one second each, bounding this fallback subcase while exercising
       the configured nameserver order. */
    if (!install_nameservers(0) ||
        !query_a("fallback.example.test", "198.51.100.18"))
        return fail("resolver-fallback");
    puts("resolver.fallback=second-server");
    return 0;
}

static int loopback_address(int family, struct sockaddr_storage *storage,
    socklen_t *length)
{
    memset(storage, 0, sizeof *storage);
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)storage;
        address->sin_family = AF_INET;
        if (inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) != 1)
            return 0;
        *length = sizeof *address;
        return 1;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)storage;
        address->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, "::1", &address->sin6_addr) != 1)
            return 0;
        *length = sizeof *address;
        return 1;
    }
    return 0;
}

static int tcp_loopback_case(int family, const char *case_name)
{
    struct sockaddr_storage address;
    socklen_t address_length;
    socklen_t actual_length;
    int listener;
    int client;
    int accepted;
    char received[8] = {0};
    const char message[] = "tcp-ok";

    if (!loopback_address(family, &address, &address_length))
        return 0;
    listener = socket(family, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address,
            address_length) != 0 || listen(listener, 1) != 0)
        return 0;
    actual_length = sizeof address;
    if (getsockname(listener, (struct sockaddr *)&address, &actual_length) != 0)
        return 0;
    client = socket(family, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&address,
            actual_length) != 0)
        return 0;
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || send(client, message, sizeof message - 1, 0) !=
            (ssize_t)(sizeof message - 1) || recv(accepted, received,
            sizeof message - 1, 0) != (ssize_t)(sizeof message - 1) ||
        memcmp(received, message, sizeof message - 1) != 0)
        return 0;
    close(accepted);
    close(client);
    close(listener);
    puts(case_name);
    return 1;
}

static int udp_loopback_case(int family, const char *case_name)
{
    struct sockaddr_storage address;
    struct sockaddr_storage source;
    socklen_t address_length;
    socklen_t actual_length;
    socklen_t source_length;
    int receiver;
    int sender;
    char received[8] = {0};
    const char message[] = "udp-ok";

    if (!loopback_address(family, &address, &address_length))
        return 0;
    receiver = socket(family, SOCK_DGRAM, 0);
    if (receiver < 0 || bind(receiver, (struct sockaddr *)&address,
            address_length) != 0)
        return 0;
    actual_length = sizeof address;
    if (getsockname(receiver, (struct sockaddr *)&address, &actual_length) != 0)
        return 0;
    sender = socket(family, SOCK_DGRAM, 0);
    if (sender < 0 || sendto(sender, message, sizeof message - 1, 0,
            (struct sockaddr *)&address, actual_length) !=
            (ssize_t)(sizeof message - 1))
        return 0;
    source_length = sizeof source;
    if (recvfrom(receiver, received, sizeof message - 1, 0,
            (struct sockaddr *)&source, &source_length) !=
            (ssize_t)(sizeof message - 1) || memcmp(received, message,
            sizeof message - 1) != 0)
        return 0;
    close(sender);
    close(receiver);
    puts(case_name);
    return 1;
}

static int socketpair_sendmsg_case(void)
{
    int sockets[2];
    struct iovec send_vectors[2];
    struct iovec receive_vectors[2];
    struct msghdr send_message;
    struct msghdr receive_message;
    char first[7] = {0};
    char second[5] = {0};
    const char left[] = "socket";
    const char right[] = "pair";

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;
    memset(&send_message, 0, sizeof send_message);
    send_vectors[0].iov_base = (void *)left;
    send_vectors[0].iov_len = sizeof left - 1;
    send_vectors[1].iov_base = (void *)right;
    send_vectors[1].iov_len = sizeof right - 1;
    send_message.msg_iov = send_vectors;
    send_message.msg_iovlen = 2;
    if (sendmsg(sockets[0], &send_message, 0) != 10) {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    memset(&receive_message, 0, sizeof receive_message);
    receive_vectors[0].iov_base = first;
    receive_vectors[0].iov_len = sizeof first - 1;
    receive_vectors[1].iov_base = second;
    receive_vectors[1].iov_len = sizeof second - 1;
    receive_message.msg_iov = receive_vectors;
    receive_message.msg_iovlen = 2;
    if (recvmsg(sockets[1], &receive_message, 0) != 10 ||
        strcmp(first, left) != 0 || strcmp(second, right) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    close(sockets[0]);
    close(sockets[1]);
    puts("network.socketpair-sendmsg-recvmsg=ok");
    return 1;
}

static int ancillary_case(void)
{
    int sockets[2] = {-1, -1};
    int data_pipe[2] = {-1, -1};
    int received_fd = -1;
    struct iovec send_vector;
    struct iovec receive_vector;
    struct msghdr send_message;
    struct msghdr receive_message;
    char send_byte = 'f';
    char receive_byte = 0;
    char control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *header;
    int sent_fd;
    char pipe_byte = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        pipe(data_pipe) != 0)
        goto fail;
    sent_fd = data_pipe[1];
    memset(&send_message, 0, sizeof send_message);
    memset(control, 0, sizeof control);
    send_vector.iov_base = &send_byte;
    send_vector.iov_len = 1;
    send_message.msg_iov = &send_vector;
    send_message.msg_iovlen = 1;
    send_message.msg_control = control;
    send_message.msg_controllen = sizeof control;
    header = CMSG_FIRSTHDR(&send_message);
    if (!header)
        goto fail;
    header->cmsg_len = CMSG_LEN(sizeof sent_fd);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(header), &sent_fd, sizeof sent_fd);

    if (sendmsg(sockets[0], &send_message, 0) != 1)
        goto fail;
    memset(&receive_message, 0, sizeof receive_message);
    receive_vector.iov_base = &receive_byte;
    receive_vector.iov_len = 1;
    receive_message.msg_iov = &receive_vector;
    receive_message.msg_iovlen = 1;
    memset(control, 0, sizeof control);
    receive_message.msg_control = control;
    receive_message.msg_controllen = sizeof control;
    if (recvmsg(sockets[1], &receive_message, 0) != 1 ||
        receive_byte != send_byte || (receive_message.msg_flags & MSG_CTRUNC))
        goto fail;
    header = CMSG_FIRSTHDR(&receive_message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS || header->cmsg_len < CMSG_LEN(sizeof(int)))
        goto fail;
    memcpy(&received_fd, CMSG_DATA(header), sizeof received_fd);
    if (received_fd < 0)
        goto fail;
    close(data_pipe[1]);
    data_pipe[1] = -1;
    if (write(received_fd, "r", 1) != 1 || read(data_pipe[0], &pipe_byte, 1) != 1 ||
        pipe_byte != 'r')
        goto fail;
    close(received_fd);
    close(data_pipe[0]);
    close(sockets[0]);
    close(sockets[1]);
    puts("network.ancillary-scm-rights=ok");
    return 1;

fail:
    if (received_fd >= 0)
        close(received_fd);
    if (data_pipe[0] >= 0)
        close(data_pipe[0]);
    if (data_pipe[1] >= 0)
        close(data_pipe[1]);
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static int epoll_case(void)
{
    int sockets[2] = {-1, -1};
    int epoll_fd = -1;
    struct epoll_event interest;
    struct epoll_event result;
    char byte = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        goto fail;
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail;
    memset(&interest, 0, sizeof interest);
    interest.events = EPOLLIN;
    interest.data.fd = sockets[1];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockets[1], &interest) != 0 ||
        epoll_wait(epoll_fd, &result, 1, 0) != 0 ||
        send(sockets[0], "e", 1, 0) != 1 ||
        epoll_wait(epoll_fd, &result, 1, 1000) != 1 ||
        result.data.fd != sockets[1] || !(result.events & EPOLLIN) ||
        recv(sockets[1], &byte, 1, 0) != 1 || byte != 'e')
        goto fail;
    close(epoll_fd);
    close(sockets[0]);
    close(sockets[1]);
    puts("network.epoll=readiness");
    return 1;

fail:
    if (epoll_fd >= 0)
        close(epoll_fd);
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static int shutdown_case(void)
{
    int sockets[2] = {-1, -1};
    char received[8] = {0};
    const char message[] = "half";

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        send(sockets[0], message, sizeof message - 1, 0) !=
            (ssize_t)(sizeof message - 1) ||
        shutdown(sockets[0], SHUT_WR) != 0 ||
        recv(sockets[1], received, sizeof message - 1, 0) !=
            (ssize_t)(sizeof message - 1) ||
        memcmp(received, message, sizeof message - 1) != 0 ||
        recv(sockets[1], received, 1, 0) != 0)
        goto fail;
    close(sockets[0]);
    close(sockets[1]);
    puts("network.shutdown-half-close=eof");
    return 1;

fail:
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static int partial_io_case(void)
{
    int sockets[2] = {-1, -1};
    int flags;
    int send_buffer = 4096;
    char payload[16384];
    int partial = 0;
    int saw_would_block = 0;
    int attempt;

    memset(payload, 'p', sizeof payload);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer,
            sizeof send_buffer) != 0)
        goto fail;
    flags = fcntl(sockets[0], F_GETFL);
    if (flags < 0 || fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) != 0)
        goto fail;
    for (attempt = 0; attempt < 64; attempt++) {
        ssize_t written = send(sockets[0], payload, sizeof payload, 0);
        if (written < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                goto fail;
            saw_would_block = 1;
            break;
        }
        if (written == 0)
            goto fail;
        if (written < (ssize_t)sizeof payload)
            partial = 1;
    }
    if (!partial || !saw_would_block)
        goto fail;
    close(sockets[0]);
    close(sockets[1]);
    puts("network.partial-send=short-write");
    return 1;

fail:
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static int socket_timeout_case(void)
{
    int sockets[2] = {-1, -1};
    struct timeval timeout;
    char byte;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
            sizeof timeout) != 0)
        goto fail;
    errno = 0;
    if (recv(sockets[0], &byte, 1, 0) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK))
        goto fail;
    close(sockets[0]);
    close(sockets[1]);
    puts("network.socket-timeout=EAGAIN");
    return 1;

fail:
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static volatile sig_atomic_t alarm_seen;

static void alarm_handler(int signal_number)
{
    (void)signal_number;
    alarm_seen = 1;
}

static int eintr_case(void)
{
    int sockets[2] = {-1, -1};
    struct sigaction action;
    struct sigaction previous;
    int handler_installed = 0;
    char byte;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        goto fail;
    memset(&action, 0, sizeof action);
    memset(&previous, 0, sizeof previous);
    action.sa_handler = alarm_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGALRM, &action, &previous) != 0)
        goto fail;
    handler_installed = 1;
    alarm_seen = 0;
    alarm(1);
    errno = 0;
    if (recv(sockets[0], &byte, 1, 0) != -1 || errno != EINTR || !alarm_seen)
        goto fail;
    alarm(0);
    sigaction(SIGALRM, &previous, NULL);
    handler_installed = 0;
    close(sockets[0]);
    close(sockets[1]);
    puts("network.eintr=EINTR");
    return 1;

fail:
    alarm(0);
    if (handler_installed)
        sigaction(SIGALRM, &previous, NULL);
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    return 0;
}

static int nonblocking_case(void)
{
    int sockets[2];
    int flags;
    char byte;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;
    flags = fcntl(sockets[0], F_GETFL);
    if (flags < 0 || fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    errno = 0;
    if (recv(sockets[0], &byte, 1, 0) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    close(sockets[0]);
    close(sockets[1]);
    puts("network.nonblocking-recv=EAGAIN");
    return 1;
}

static int readiness_case(void)
{
    int sockets[2];
    struct pollfd descriptor;
    fd_set read_set;
    struct timeval timeout;
    char byte;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;
    descriptor.fd = sockets[1];
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (poll(&descriptor, 1, 0) != 0 || descriptor.revents != 0 ||
        send(sockets[0], "p", 1, 0) != 1 || poll(&descriptor, 1, 0) != 1 ||
        !(descriptor.revents & POLLIN) || recv(sockets[1], &byte, 1, 0) != 1 ||
        byte != 'p') {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    FD_ZERO(&read_set);
    FD_SET(sockets[1], &read_set);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    if (select(sockets[1] + 1, &read_set, NULL, NULL, &timeout) != 0 ||
        send(sockets[0], "s", 1, 0) != 1) {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    FD_ZERO(&read_set);
    FD_SET(sockets[1], &read_set);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    if (select(sockets[1] + 1, &read_set, NULL, NULL, &timeout) != 1 ||
        !FD_ISSET(sockets[1], &read_set) || recv(sockets[1], &byte, 1, 0) != 1 ||
        byte != 's') {
        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }
    close(sockets[0]);
    close(sockets[1]);
    puts("network.poll-select=readiness");
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 1)
        return fail("arguments");
    if (resolver_cases() != 0)
        return 1;
    if (!tcp_loopback_case(AF_INET, "network.tcp4=loopback") ||
        !tcp_loopback_case(AF_INET6, "network.tcp6=loopback") ||
        !udp_loopback_case(AF_INET, "network.udp4=loopback") ||
        !udp_loopback_case(AF_INET6, "network.udp6=loopback") ||
        !socketpair_sendmsg_case() || !ancillary_case() || !epoll_case() ||
        !shutdown_case() || !partial_io_case() || !socket_timeout_case() ||
        !eintr_case() || !nonblocking_case() || !readiness_case())
        return fail("socket-network");
    return 0;
}
