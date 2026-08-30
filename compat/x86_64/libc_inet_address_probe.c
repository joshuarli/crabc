/* Static crabc-libc x86-64 numeric Internet-address codec fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * through one freestanding executable linked solely with the selected crabc
 * archive. It selects only inet_pton, inet_ntop, inet_aton, and inet_addr
 * (plus musl's hidden __inet_aton implementation identity). The cases pin
 * strict IPv4/IPv6 text grammar, legacy inet_aton bases and abbreviations,
 * network-byte-order storage, the inet_addr INADDR_NONE ambiguity, and the
 * deliberately different AF_INET/AF_INET6 short-buffer write contracts.
 * It does not select DNS, resolver state, netdb, interface lookup, inet_ntoa
 * scratch storage, allocation, stdio, libc.so, CRT, loader, or public x86
 * support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4 &&
    sizeof(in_port_t) == 2 && _Alignof(in_port_t) == 2,
    "x86 inet scalar widths");
_Static_assert(sizeof(socklen_t) == 4 && _Alignof(socklen_t) == 4 &&
    sizeof(struct in_addr) == 4 && _Alignof(struct in_addr) == 4 &&
    offsetof(struct in_addr, s_addr) == 0,
    "x86 inet address records");
_Static_assert(AF_INET == 2 && AF_INET6 == 10 && AF_UNIX == 1 &&
    INET_ADDRSTRLEN == 16 && INET6_ADDRSTRLEN == 46,
    "x86 selected address constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_pton),
    int (*)(int, const char *, void *)), "inet_pton declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_ntop),
    const char *(*)(int, const void *, char *, socklen_t)),
    "inet_ntop declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_aton),
    int (*)(const char *, struct in_addr *)), "inet_aton declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_addr),
    in_addr_t (*)(const char *)), "inet_addr declaration");

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static void fill_bytes(unsigned char *bytes, size_t count, unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index) bytes[index] = value;
}

static int bytes_are(const unsigned char *bytes, size_t count, unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (bytes[index] != value) return 0;
    return 1;
}

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int check_inet_pton(void)
{
    static const unsigned char ipv4[] = { 192, 0, 2, 1 };
    static const unsigned char ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const unsigned char mapped[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff, 192, 0, 2, 128,
    };
    static const unsigned char partial_ipv4[] = { 1, 2, 3, 0xa5 };
    static const unsigned char complete_ipv4[] = { 1, 2, 3, 4 };
    static const unsigned char compatible[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 192, 0, 2, 1,
    };
    static const unsigned char partial_mapped[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff, 192, 0, 2, 0,
    };
    unsigned char actual[16];

    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET, "192.0.2.1", actual) != 1 ||
        !bytes_equal(actual, ipv4, sizeof(ipv4)) || errno != E2BIG)
        return 1;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET6, "2001:db8::1", actual) != 1 ||
        !bytes_equal(actual, ipv6, sizeof(ipv6)) || errno != E2BIG)
        return 2;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET6, "::ffff:192.0.2.128", actual) != 1 ||
        !bytes_equal(actual, mapped, sizeof(mapped)) || errno != E2BIG)
        return 3;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET6, "::192.0.2.1", actual) != 1 ||
        !bytes_equal(actual, compatible, sizeof(compatible)) || errno != E2BIG)
        return 4;

    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET, "1.2.3", actual) != 0 ||
        !bytes_equal(actual, partial_ipv4, sizeof(partial_ipv4)) || errno != E2BIG)
        return 5;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET, "01.2.3.4", actual) != 0 ||
        !bytes_are(actual, sizeof(actual), 0xa5) || errno != E2BIG)
        return 6;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET, "1.2.3.4x", actual) != 0 ||
        !bytes_equal(actual, complete_ipv4, sizeof(complete_ipv4)) || errno != E2BIG)
        return 7;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET6, "2001:db8::xyz", actual) != 0 ||
        !bytes_are(actual, sizeof(actual), 0xa5) || errno != E2BIG)
        return 8;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_INET6, "::ffff:192.0.2.999", actual) != 0 ||
        !bytes_equal(actual, partial_mapped, sizeof(partial_mapped)) || errno != E2BIG)
        return 9;
    fill_bytes(actual, sizeof(actual), 0xa5);
    errno = E2BIG;
    if (inet_pton(AF_UNIX, "192.0.2.1", actual) != -1 || errno != EAFNOSUPPORT ||
        !bytes_are(actual, sizeof(actual), 0xa5))
        return 10;
    return 0;
}

static int check_inet_ntop(void)
{
    static const unsigned char ipv4[] = { 192, 0, 2, 1 };
    static const unsigned char ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const unsigned char tie[] = {
        0x20, 0x01, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 1, 0, 1,
    };
    static const unsigned char leading_tie[] = {
        0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 1, 0, 1, 0, 1,
    };
    static const unsigned char mapped[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff, 192, 0, 2, 128,
    };
    static const unsigned char compatible[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 192, 0, 2, 128,
    };
    char output[INET6_ADDRSTRLEN];
    const char *result;

    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET, ipv4, output, sizeof(output));
    if (result != output || !text_equal(output, "192.0.2.1") || errno != E2BIG)
        return 1;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, ipv6, output, sizeof(output));
    if (result != output || !text_equal(output, "2001:db8::1") || errno != E2BIG)
        return 2;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, tie, output, sizeof(output));
    if (result != output || !text_equal(output, "2001::1:0:0:1:1") || errno != E2BIG)
        return 3;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, leading_tie, output, sizeof(output));
    if (result != output || !text_equal(output, "::1:0:0:1:1:1") || errno != E2BIG)
        return 4;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, mapped, output, sizeof(output));
    if (result != output || !text_equal(output, "::ffff:192.0.2.128") || errno != E2BIG)
        return 5;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, compatible, output, sizeof(output));
    if (result != output || !text_equal(output, "::c000:280") || errno != E2BIG)
        return 6;

    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET, ipv4, output, 9);
    if (result != NULL || errno != ENOSPC ||
        !bytes_equal((const unsigned char *)output,
            (const unsigned char[]) { '1', '9', '2', '.', '0', '.', '2', '.', '\0' },
            9))
        return 7;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET, ipv4, output, 0);
    if (result != NULL || errno != ENOSPC || (unsigned char)output[0] != 0xa5)
        return 8;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, ipv6, output, 12);
    if (result != output || !text_equal(output, "2001:db8::1") || errno != E2BIG)
        return 9;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_INET6, ipv6, output, 11);
    if (result != NULL || errno != ENOSPC ||
        !bytes_are((const unsigned char *)output, sizeof(output), 0xa5))
        return 10;
    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    result = inet_ntop(AF_UNIX, ipv4, output, sizeof(output));
    if (result != NULL || errno != EAFNOSUPPORT || (unsigned char)output[0] != 0xa5)
        return 11;
    return 0;
}

static int check_inet_aton_and_addr(void)
{
    static const unsigned char ipv4[] = { 192, 0, 2, 1 };
    static const unsigned char abbreviated[] = { 127, 0, 0, 1 };
    static const unsigned char all_ones[] = { 255, 255, 255, 255 };
    static const unsigned char partial[] = { 1, 2, 3, 0xa5 };
    struct in_addr address;
    struct in_addr parsed;

    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("192.0.2.1", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, ipv4, sizeof(ipv4)) ||
        errno != E2BIG)
        return 1;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("127.1", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, abbreviated, sizeof(abbreviated)) ||
        errno != E2BIG)
        return 2;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("0x7f.1", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, abbreviated, sizeof(abbreviated)) ||
        errno != E2BIG)
        return 3;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("0177.1", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, abbreviated, sizeof(abbreviated)) ||
        errno != E2BIG)
        return 4;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("127.0.1", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, abbreviated, sizeof(abbreviated)) ||
        errno != E2BIG)
        return 5;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("0xffffffff", &address) != 1 ||
        !bytes_equal((const unsigned char *)&address, all_ones, sizeof(all_ones)) ||
        errno != E2BIG)
        return 6;

    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("1.2.3.999", &address) != 0 ||
        !bytes_equal((const unsigned char *)&address, partial, sizeof(partial)) ||
        errno != E2BIG)
        return 7;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("not-an-address", &address) != 0 || errno != EINVAL ||
        !bytes_are((const unsigned char *)&address, sizeof(address), 0xa5))
        return 8;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("+1", &address) != 0 || errno != E2BIG ||
        !bytes_are((const unsigned char *)&address, sizeof(address), 0xa5))
        return 9;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton(" 1", &address) != 0 || errno != E2BIG ||
        !bytes_are((const unsigned char *)&address, sizeof(address), 0xa5))
        return 10;
    fill_bytes((unsigned char *)&address, sizeof(address), 0xa5);
    errno = E2BIG;
    if (inet_aton("18446744073709551616", &address) != 0 || errno != ERANGE ||
        !bytes_are((const unsigned char *)&address, sizeof(address), 0xa5))
        return 11;

    errno = E2BIG;
    if (inet_aton("192.0.2.1", &parsed) != 1 ||
        inet_addr("192.0.2.1") != parsed.s_addr || errno != E2BIG)
        return 12;
    errno = E2BIG;
    if (inet_addr("255.255.255.255") != (in_addr_t)-1 ||
        inet_addr("not-an-address") != (in_addr_t)-1 || errno != EINVAL)
        return 13;
    return 0;
}

int crabc_x86_64_inet_address_probe(void)
{
    int status;

    status = check_inet_pton();
    if (status != 0) return 10 + status;
    status = check_inet_ntop();
    if (status != 0) return 30 + status;
    status = check_inet_aton_and_addr();
    if (status != 0) return 50 + status;
    return 0;
}

#ifndef CRABC_INET_ADDRESS_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_address_probe();
}
#endif
