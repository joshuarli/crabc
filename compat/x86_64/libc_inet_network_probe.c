/* Static crabc-libc x86-64 legacy IPv4 textual-network fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * through a freestanding executable that starts with the directly extracted
 * inet_network object and reaches the existing selected inet_addr parser only
 * through the normal demand-driven crabc archive. The cases retain musl's
 * numeric IPv4 grammar, including abbreviated and base-zero forms, but this
 * leaf is not resolver, DNS, hosts/resolv.conf, netdb, interface, socket, or
 * byte-order-helper behavior.
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

typedef in_addr_t (*inet_network_signature)(const char *);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4 &&
    sizeof(struct in_addr) == 4 && _Alignof(struct in_addr) == 4 &&
    offsetof(struct in_addr, s_addr) == 0,
    "x86 IPv4 address ABI");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_network), inet_network_signature),
    "inet_network declaration");

static int check_network(const char *text, in_addr_t expected)
{
    return inet_network(text) != expected;
}

int crabc_x86_64_inet_network_probe(void)
{
    if (check_network("0.0.0.0", 0x00000000U)) return 1;
    if (check_network("127.18.52.86", 0x7f123456U)) return 2;
    if (check_network("128.18.52.86", 0x80123456U)) return 3;
    if (check_network("191.171.205.239", 0xbfabcdefU)) return 4;
    if (check_network("192.18.52.86", 0xc0123456U)) return 5;
    if (check_network("127.1", 0x7f000001U)) return 6;
    if (check_network("0177.1", 0x7f000001U)) return 7;
    if (check_network("255.255.255.255", 0xffffffffU)) return 8;
    if (check_network("256.0.0.1", 0xffffffffU)) return 9;
    errno = E2BIG;
    if (inet_network("18446744073709551616") != 0xffffffffU || errno != ERANGE)
        return 10;
    errno = E2BIG;
    if (inet_network("not-an-address") != 0xffffffffU || errno != EINVAL)
        return 11;
    return 0;
}

#ifndef CRABC_INET_NETWORK_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_network_probe();
}
#endif
