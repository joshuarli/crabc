/* Static crabc-libc x86-64 deterministic numeric netdb fixture.
 *
 * The same project-header C body first executes with pinned musl 1.2.6 and
 * then in a freestanding -nostdlib/static candidate linked only through the
 * selected crabc archive. It covers only numeric getaddrinfo/freeaddrinfo,
 * numeric-fallback getnameinfo, and gai_strerror. No case reads /etc/hosts or
 * /etc/resolv.conf, performs service lookup, or sends DNS traffic.
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
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(socklen_t) == 4 && _Alignof(socklen_t) == 4,
    "x86 socklen_t ABI");
_Static_assert(sizeof(struct addrinfo) == 48 && _Alignof(struct addrinfo) == 8 &&
    offsetof(struct addrinfo, ai_flags) == 0 &&
    offsetof(struct addrinfo, ai_family) == 4 &&
    offsetof(struct addrinfo, ai_socktype) == 8 &&
    offsetof(struct addrinfo, ai_protocol) == 12 &&
    offsetof(struct addrinfo, ai_addrlen) == 16 &&
    offsetof(struct addrinfo, ai_addr) == 24 &&
    offsetof(struct addrinfo, ai_canonname) == 32 &&
    offsetof(struct addrinfo, ai_next) == 40,
    "x86 addrinfo ABI");
_Static_assert(sizeof(struct sockaddr_in) == 16 && sizeof(struct sockaddr_in6) == 28 &&
    offsetof(struct sockaddr_in, sin_family) == 0 &&
    offsetof(struct sockaddr_in, sin_port) == 2 &&
    offsetof(struct sockaddr_in, sin_addr) == 4 &&
    offsetof(struct sockaddr_in6, sin6_addr) == 8 &&
    offsetof(struct sockaddr_in6, sin6_scope_id) == 24,
    "x86 Internet socket ABI");
_Static_assert(AI_PASSIVE == 0x0001 && AI_CANONNAME == 0x0002 &&
    AI_NUMERICHOST == 0x0004 && AI_V4MAPPED == 0x0008 && AI_ALL == 0x0010 &&
    AI_ADDRCONFIG == 0x0020 && AI_NUMERICSERV == 0x0400,
    "selected getaddrinfo flags");
_Static_assert(NI_NUMERICHOST == 0x01 && NI_NUMERICSERV == 0x02 &&
    NI_NOFQDN == 0x04 && NI_NAMEREQD == 0x08 && NI_DGRAM == 0x10 &&
    NI_NUMERICSCOPE == 0x100,
    "selected getnameinfo flags");
_Static_assert(EAI_BADFLAGS == -1 && EAI_NONAME == -2 && EAI_FAMILY == -6 &&
    EAI_SOCKTYPE == -7 && EAI_SERVICE == -8 && EAI_MEMORY == -10 &&
    EAI_SYSTEM == -11 && EAI_OVERFLOW == -12,
    "selected EAI values");
_Static_assert(CRABC_TYPE_IS(__typeof__(&getaddrinfo),
    int (*)(const char *restrict, const char *restrict,
        const struct addrinfo *restrict, struct addrinfo **restrict)),
    "getaddrinfo declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&freeaddrinfo),
    void (*)(struct addrinfo *)), "freeaddrinfo declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&getnameinfo),
    int (*)(const struct sockaddr *restrict, socklen_t, char *restrict,
        socklen_t, char *restrict, socklen_t, int)), "getnameinfo declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&gai_strerror),
    const char *(*)(int)), "gai_strerror declaration");

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t count)
{
    size_t index;
    for (index = 0; index < count; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static int check_numeric_v4(void)
{
    static const unsigned char expected[] = { 192, 0, 2, 9 };
    struct addrinfo hints = { 0 };
    struct addrinfo *result = (struct addrinfo *)(uintptr_t)1;
    struct sockaddr_in *address;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV;
    errno = E2BIG;
    if (getaddrinfo("192.0.2.9", "443", &hints, &result) != 0) return 1;
    if (result == NULL) return 2;
    if (result->ai_next != NULL) { freeaddrinfo(result); return 3; }
    if (result->ai_flags != 0) { freeaddrinfo(result); return 4; }
    if (result->ai_family != AF_INET) { freeaddrinfo(result); return 5; }
    if (result->ai_socktype != SOCK_STREAM || result->ai_protocol != IPPROTO_TCP) {
        freeaddrinfo(result); return 6;
    }
    if (result->ai_addrlen != sizeof(*address)) { freeaddrinfo(result); return 7; }
    if (result->ai_canonname == NULL || !text_equal(result->ai_canonname, "192.0.2.9")) {
        freeaddrinfo(result); return 8;
    }
    if (errno != E2BIG) { freeaddrinfo(result); return 9; }
    address = (struct sockaddr_in *)result->ai_addr;
    if (address == NULL || address->sin_family != AF_INET ||
        address->sin_port != 0xbb01 ||
        !bytes_equal((const unsigned char *)&address->sin_addr, expected, sizeof(expected))) {
        freeaddrinfo(result);
        return 2;
    }
    freeaddrinfo(result);
    return 0;
}

static int check_numeric_v4mapped(void)
{
    static const unsigned char expected[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 4,
    };
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL;
    struct sockaddr_in6 *address;

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_V4MAPPED | AI_NUMERICHOST;
    if (getaddrinfo("198.51.100.4", "53", &hints, &result) != 0) return 1;
    if (result == NULL) return 2;
    if (result->ai_next != NULL) { freeaddrinfo(result); return 3; }
    address = (struct sockaddr_in6 *)result->ai_addr;
    if (result->ai_family != AF_INET6 || result->ai_addrlen != sizeof(*address) ||
        address == NULL || address->sin6_family != AF_INET6 ||
        address->sin6_port != 0x3500 || address->sin6_scope_id != 0 ||
        !bytes_equal(address->sin6_addr.s6_addr, expected, sizeof(expected))) {
        freeaddrinfo(result);
        return 2;
    }
    freeaddrinfo(result);
    return 0;
}

static int check_passive_default(void)
{
    static const unsigned char zeros[4] = { 0, 0, 0, 0 };
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL;
    struct sockaddr_in *address;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, "53", &hints, &result) != 0 || result == NULL)
        return 1;
    address = (struct sockaddr_in *)result->ai_addr;
    if (address == NULL || address->sin_family != AF_INET ||
        address->sin_port != 0x3500 ||
        !bytes_equal((const unsigned char *)&address->sin_addr, zeros, sizeof(zeros))) {
        freeaddrinfo(result);
        return 2;
    }
    freeaddrinfo(result);
    return 0;
}

static int check_nameinfo(void)
{
    struct sockaddr_in6 address = { 0 };
    char host[46];
    char service[6];
    char short_host[3] = { 'x', 'y', 'z' };

    address.sin6_family = AF_INET6;
    address.sin6_port = 0xbb01;
    address.sin6_addr.s6_addr[0] = 0x20;
    address.sin6_addr.s6_addr[1] = 0x01;
    address.sin6_addr.s6_addr[2] = 0x0d;
    address.sin6_addr.s6_addr[3] = 0xb8;
    address.sin6_addr.s6_addr[15] = 1;
    errno = E2BIG;
    if (getnameinfo((const struct sockaddr *)&address, sizeof(address), host,
            sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0 ||
        !text_equal(host, "2001:db8::1") || !text_equal(service, "443") || errno != E2BIG)
        return 1;
    if (getnameinfo((const struct sockaddr *)&address, sizeof(address), short_host,
            sizeof(short_host), NULL, 0, NI_NUMERICHOST) != EAI_OVERFLOW ||
        short_host[0] != 'x' || short_host[1] != 'y' || short_host[2] != 'z')
        return 2;
    if (getnameinfo((const struct sockaddr *)&address, sizeof(address), host,
            sizeof(host), NULL, 0, NI_NAMEREQD) != EAI_NONAME)
        return 3;
    return 0;
}

static int check_errors(void)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = (struct addrinfo *)(uintptr_t)1;

    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_INET;
    if (getaddrinfo("example.invalid", "1", &hints, &result) != EAI_NONAME)
        return 1;
    if (getaddrinfo("192.0.2.1", "https", &hints, &result) != EAI_NONAME)
        return 2;
    hints.ai_family = 12345;
    if (getaddrinfo("192.0.2.1", "1", &hints, &result) != EAI_FAMILY)
        return 3;
    if (!text_equal(gai_strerror(EAI_NONAME), "Name does not resolve") ||
        !text_equal(gai_strerror(EAI_OVERFLOW), "Overflow"))
        return 4;
    return 0;
}

int crabc_x86_64_numeric_netdb_probe(void)
{
    int result;
    if ((result = check_numeric_v4()) != 0) return result;
    if ((result = check_numeric_v4mapped()) != 0) return 10 + result;
    if ((result = check_passive_default()) != 0) return 20 + result;
    if ((result = check_nameinfo()) != 0) return 30 + result;
    if ((result = check_errors()) != 0) return 40 + result;
    return 0;
}

#ifndef CRABC_NUMERIC_NETDB_FREESTANDING
int main(void)
{
    return crabc_x86_64_numeric_netdb_probe();
}
#endif
