/* Static crabc-libc x86-64 immutable IPv6 loopback-address differential.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through an archive-free static candidate containing only the extracted
 * `in6addr_loopback` object. It proves the public immutable final-octet-one
 * object, not IPv6 socket transport, address conversion, resolver state, DNS,
 * netdb, interfaces, Ethernet, or the separate in6addr_any object.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef const struct in6_addr *in6addr_loopback_pointer;

_Static_assert(sizeof(struct in6_addr) == 16 && _Alignof(struct in6_addr) == 4,
    "x86 IPv6 address ABI");
_Static_assert(offsetof(struct in6_addr, s6_addr) == 0,
    "x86 IPv6 address byte offset");
_Static_assert(CRABC_TYPE_IS(__typeof__(&in6addr_loopback),
    in6addr_loopback_pointer), "in6addr_loopback declaration");

static int is_loopback(const volatile struct in6_addr *address)
{
    size_t index;

    if (!address)
        return 0;
    for (index = 0; index < sizeof(address->s6_addr) - 1; index++) {
        if (address->s6_addr[index] != 0)
            return 0;
    }
    return address->s6_addr[15] == 1;
}

int crabc_x86_64_in6addr_loopback_probe(void)
{
    const volatile struct in6_addr *first = &in6addr_loopback;
    const volatile struct in6_addr *second = &in6addr_loopback;
    const struct in6_addr *address = (const struct in6_addr *)first;

    if (first != second)
        return 1;
    if (!is_loopback(first))
        return 2;
    if (!IN6_IS_ADDR_LOOPBACK(address))
        return 3;
    if (IN6_IS_ADDR_UNSPECIFIED(address) || IN6_IS_ADDR_MULTICAST(address) ||
        IN6_IS_ADDR_V4COMPAT(address))
        return 4;
    return 0;
}

#ifndef CRABC_IN6ADDR_LOOPBACK_FREESTANDING
int main(void)
{
    return crabc_x86_64_in6addr_loopback_probe();
}
#endif
