/* Hermetic x86-64 C resolver-runtime probe.
 *
 * The process starts a local UDP DNS fixture before entering a temporary
 * chroot containing only fixture /etc/hosts and /etc/resolv.conf. The same C
 * body first executes through pinned musl and then through the feature-gated
 * crabc archive. No ambient hosts, resolver configuration, or external DNS
 * service can affect either result.
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
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* `<netdb.h>` intentionally hides the compatibility object behind its
 * accessor macro. This alternate spelling lets the differential prove musl's
 * main-thread fallback object separately from a selected worker's TLS slot. */
extern int crabc_link_visible_h_errno __asm__("h_errno");

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] && right[index]) {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;
    for (index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static long raw_syscall1(long number, long argument)
{
    long result;
    __asm__ volatile ("syscall" : "=a"(result) : "a"(number), "D"(argument)
        : "rcx", "r11", "memory");
    return result;
}

static int enter_fixture_root(const char *root)
{
    /* Linux/x86-64 chroot=161 and chdir=80. This harness-only transition
     * makes the library's fixed /etc paths hermetic; it is not an archive API
     * dependency. */
    if (raw_syscall1(161, (long)(uintptr_t)root) < 0) return -1;
    return raw_syscall1(80, (long)(uintptr_t)"/") < 0 ? -1 : 0;
}

static size_t question_end(const unsigned char *packet, size_t length)
{
    size_t offset = 12;
    while (offset < length) {
        unsigned char label = packet[offset++];
        if (label == 0) return offset + 4 <= length ? offset + 4 : 0;
        if ((label & 0xc0) || label > 63 || offset + label > length) return 0;
        offset += label;
    }
    return 0;
}

static unsigned question_type(const unsigned char *packet, size_t end)
{
    return ((unsigned)packet[end - 4] << 8) | packet[end - 3];
}

static int question_matches(const unsigned char *packet, size_t length,
    const unsigned char *name, size_t name_length, unsigned type)
{
    size_t end = question_end(packet, length);
    return end != 0 && end - 4 == 12 + name_length &&
        bytes_equal(packet + 12, name, name_length) &&
        question_type(packet, end) == type && packet[end - 2] == 0 &&
        packet[end - 1] == C_IN;
}

static size_t append_u16(unsigned char *packet, size_t offset, unsigned value)
{
    packet[offset++] = (unsigned char)(value >> 8);
    packet[offset++] = (unsigned char)value;
    return offset;
}

static size_t append_u32(unsigned char *packet, size_t offset, uint32_t value)
{
    packet[offset++] = (unsigned char)(value >> 24);
    packet[offset++] = (unsigned char)(value >> 16);
    packet[offset++] = (unsigned char)(value >> 8);
    packet[offset++] = (unsigned char)value;
    return offset;
}

struct expected_question {
    const unsigned char *name;
    size_t name_length;
    unsigned type;
    int missing;
};

static const unsigned char dns_fixture_name[] = {
    3, 'd', 'n', 's', 7, 'f', 'i', 'x', 't', 'u', 'r', 'e',
    4, 't', 'e', 's', 't', 0,
};
static const unsigned char missing_fixture_name[] = {
    7, 'm', 'i', 's', 's', 'i', 'n', 'g', 7, 'f', 'i', 'x', 't',
    'u', 'r', 'e', 4, 't', 'e', 's', 't', 0,
};
static const unsigned char dns_name[] = { 3, 'd', 'n', 's', 0 };

static const struct expected_question expected_questions[] = {
    { dns_fixture_name, sizeof(dns_fixture_name), T_A, 0 },
    { dns_fixture_name, sizeof(dns_fixture_name), T_A, 0 },
    { dns_fixture_name, sizeof(dns_fixture_name), T_A, 0 },
    { dns_fixture_name, sizeof(dns_fixture_name), T_A, 0 },
    { missing_fixture_name, sizeof(missing_fixture_name), T_A, 1 },
    { dns_name, sizeof(dns_name), T_A, 0 },
};

static int serve_dns(int descriptor)
{
    unsigned iteration;
    for (iteration = 0; iteration < sizeof(expected_questions) / sizeof(expected_questions[0]); ++iteration) {
        unsigned char request[512];
        unsigned char response[512];
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);
        ssize_t received = recvfrom(descriptor, request, sizeof(request), 0,
            (struct sockaddr *)&peer, &peer_length);
        size_t end, offset;
        const struct expected_question *expected = &expected_questions[iteration];
        if (received < 12) return 1;
        end = question_end(request, (size_t)received);
        if (end == 0) return 2;
        if (!question_matches(request, (size_t)received, expected->name,
                expected->name_length, expected->type))
            return 3;
        response[0] = request[0]; response[1] = request[1];
        response[2] = 0x81; response[3] = expected->missing ? 0x83 : 0x80;
        response[4] = 0; response[5] = 1;
        response[6] = 0; response[7] = expected->missing ? 0 : 2;
        response[8] = response[9] = response[10] = response[11] = 0;
        for (offset = 12; offset < end; ++offset) response[offset] = request[offset];
        if (!expected->missing) {
            static const unsigned char cname[] = {
                9, 'c','a','n','o','n','i','c','a','l',
                7, 'f','i','x','t','u','r','e',
                4, 't','e','s','t', 0,
            };
            response[offset++] = 0xc0; response[offset++] = 0x0c;
            offset = append_u16(response, offset, 5);
            offset = append_u16(response, offset, 1);
            offset = append_u32(response, offset, 0);
            offset = append_u16(response, offset, sizeof(cname));
            for (size_t index = 0; index < sizeof(cname); ++index)
                response[offset++] = cname[index];
            response[offset++] = 0xc0; response[offset++] = 0x0c;
            offset = append_u16(response, offset, 1);
            offset = append_u16(response, offset, 1);
            offset = append_u32(response, offset, 0);
            offset = append_u16(response, offset, 4);
            response[offset++] = 203; response[offset++] = 0;
            response[offset++] = 113; response[offset++] = 9;
        }
        if (sendto(descriptor, response, offset, 0, (struct sockaddr *)&peer,
                peer_length) != (ssize_t)offset)
            return 4;
    }
    return 0;
}

static int start_dns_server(void)
{
    struct sockaddr_in address = { 0 };
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    pid_t child;
    if (descriptor < 0) return -1;
    address.sin_family = AF_INET;
    address.sin_port = htons(53);
    address.sin_addr.s_addr = htonl(0x7f000001u);
    if (bind(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return -1;
    }
    child = fork();
    if (child < 0) {
        close(descriptor);
        return -1;
    }
    if (child == 0) {
        int result = serve_dns(descriptor);
        close(descriptor);
        _exit(result);
    }
    close(descriptor);
    return child;
}

static int check_addrinfo(const char *name, const unsigned char expected[4],
    const char *canonical)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = 0;
    struct sockaddr_in *address;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(name, "443", &hints, &result) != 0 || result == 0) return 1;
    address = (struct sockaddr_in *)result->ai_addr;
    if (result->ai_next != 0 || result->ai_family != AF_INET ||
        result->ai_socktype != SOCK_STREAM || result->ai_protocol != IPPROTO_TCP ||
        result->ai_addrlen != sizeof(*address) || address == 0 ||
        address->sin_port != htons(443) ||
        !bytes_equal((const unsigned char *)&address->sin_addr, expected, 4) ||
        result->ai_canonname == 0 || !text_equal(result->ai_canonname, canonical)) {
        freeaddrinfo(result);
        return 2;
    }
    freeaddrinfo(result);
    return 0;
}

/* This stays inside the already selected one-worker pthread seam. It proves
 * the public h_errno macro reaches a distinct worker slot without treating
 * the resolver package as a general pthread/runtime claim. */
struct h_errno_thread_context {
    int *main_location;
    int *worker_location;
    int worker_value;
};

static void *check_h_errno_worker(void *opaque)
{
    struct h_errno_thread_context *context = opaque;

    context->worker_location = __h_errno_location();
    if (!context->worker_location ||
        context->worker_location == context->main_location)
        return (void *)(uintptr_t)1;
    h_errno = TRY_AGAIN;
    context->worker_value = h_errno;
    if (*context->worker_location != TRY_AGAIN)
        return (void *)(uintptr_t)2;
    return 0;
}

static int check_thread_local_h_errno(void)
{
    struct h_errno_thread_context context = { 0 };
    pthread_t thread;
    void *worker_result = 0;

    context.main_location = __h_errno_location();
    if (!context.main_location) return 1;
    h_errno = NO_RECOVERY;
    if (pthread_create(&thread, 0, check_h_errno_worker, &context) != 0)
        return 2;
    if (pthread_join(thread, &worker_result) != 0)
        return 3;
    if (worker_result || !context.worker_location ||
        context.worker_location == context.main_location ||
        context.worker_value != TRY_AGAIN || h_errno != NO_RECOVERY)
        return 4;
    return 0;
}

int crabc_x86_64_resolver_runtime_probe(int argc, char **argv)
{
    static const unsigned char host_address[4] = { 192, 0, 2, 44 };
    static const unsigned char dns_address[4] = { 203, 0, 113, 9 };
    static const unsigned char compressed_name[] = {
        3, 'd', 'n', 's', 7, 'f', 'i', 'x', 't', 'u', 'r', 'e',
        4, 't', 'e', 's', 't', 0,
    };
    unsigned char answer[512];
    unsigned char query[512];
    unsigned char compressed[sizeof(compressed_name)];
    struct __res_state *state;
    int query_length, server, status, result;

    if (argc != 2) return 1;
    server = start_dns_server();
    if (server < 0) return 2;
    if (enter_fixture_root(argv[1]) != 0) return 3;
    errno = E2BIG;
    h_errno = NO_RECOVERY;
    if (res_init() != 0) return 4;
    if (__h_errno_location() != &crabc_link_visible_h_errno)
        return 39;
#ifdef CRABC_RESOLVER_RUNTIME_FREESTANDING
    /* musl keeps this historical state record deliberately minimal. The
     * opt-in crabc package instead makes the C-owned record an observable
     * configuration boundary, so inspect it only on that arm. */
    state = __res_state();
    if (state == 0 || state->nscount != 1 || state->retrans != 1 ||
        state->retry != 1 || state->ndots != 1 || state->dnsrch[0] == 0 ||
        !text_equal(state->dnsrch[0], "fixture.test") || h_errno != 0 ||
        state->res_h_errno != 0 || __h_errno_location() != &h_errno ||
        errno != E2BIG)
        return 5;
#else
    (void)state;
#endif
    if (check_thread_local_h_errno() != 0)
        return 38;
    query_length = res_mkquery(QUERY, "dns.fixture.test", C_IN, T_A, 0, 0,
        0, query, sizeof(query));
    if (query_length < 12 || query[2] != 1 || query[5] != 1)
        return 6;
    errno = E2BIG;
    if (dn_comp("dns.fixture.test", compressed, sizeof(compressed), 0, 0) !=
            (int)sizeof(compressed_name) ||
        !bytes_equal(compressed, compressed_name, sizeof(compressed_name)) ||
        errno != E2BIG)
        return 8;
    errno = E2BIG;
    if (dn_comp("dns.fixture.test", compressed, sizeof(compressed) - 1, 0, 0) != -1 ||
        errno != E2BIG)
        return 9;
    if (res_send(query, query_length, answer, sizeof(answer)) < 12)
        return 7;
    if ((result = check_addrinfo("host-alias", host_address, "host.fixture")) != 0)
        return 10 + result;
    if ((result = check_addrinfo("dns", dns_address, "canonical.fixture.test")) != 0)
        return 20 + result;
    if (res_query("dns.fixture.test", C_IN, T_A, answer, sizeof(answer)) < 12)
        return 30;
#ifdef CRABC_RESOLVER_RUNTIME_FREESTANDING
    if (h_errno != 0 || state->res_h_errno != 0)
        return 31;
#endif
    if (res_querydomain("dns", "fixture.test", C_IN, T_A, answer,
            sizeof(answer)) < 12)
        return 40;
#ifdef CRABC_RESOLVER_RUNTIME_FREESTANDING
    if (h_errno != 0 || state->res_h_errno != 0)
        return 41;
#endif
    if (res_query("missing.fixture.test", C_IN, T_A, answer, sizeof(answer)) != -1)
        return 32;
    if (h_errno != HOST_NOT_FOUND)
        return 33;
#ifdef CRABC_RESOLVER_RUNTIME_FREESTANDING
    if (state->res_h_errno != HOST_NOT_FOUND)
        return 34;
#endif
    if (res_search != res_query)
        return 42;
    if (res_search("dns", C_IN, T_A, answer, sizeof(answer)) < 12)
        return 35;
#ifdef CRABC_RESOLVER_RUNTIME_FREESTANDING
    if (h_errno != 0)
        return 36;
#endif
    if (waitpid(server, &status, 0) != server || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 37;
    return 0;
}

#ifndef CRABC_RESOLVER_RUNTIME_FREESTANDING
int main(int argc, char **argv)
{
    return crabc_x86_64_resolver_runtime_probe(argc, argv);
}
#endif
