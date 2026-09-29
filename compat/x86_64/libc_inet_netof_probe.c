/* Static C IPv4 classful network-part differential. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CRABC_INET_NETOF_FREESTANDING
#include <errno.h>
#endif

typedef in_addr_t (*inet_netof_signature)(struct in_addr);

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4,
    "x86 in_addr_t layout");
_Static_assert(sizeof(struct in_addr) == 4, "x86 in_addr layout");
_Static_assert(_Alignof(struct in_addr) == 4, "x86 in_addr alignment");
_Static_assert(offsetof(struct in_addr, s_addr) == 0, "x86 in_addr offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_netof),
    inet_netof_signature), "inet_netof declaration");

static struct in_addr address_from_raw(in_addr_t raw)
{
    struct in_addr address;

    address.s_addr = raw;
    return address;
}

/* A network-order octet sequence occupies the reversed raw word on x86-64. */
static struct in_addr address_from_octets(unsigned a, unsigned b,
    unsigned c, unsigned d)
{
    return address_from_raw(a | b << 8 | c << 16 | d << 24);
}

static int check_address(struct in_addr address, in_addr_t expected)
{
#ifndef CRABC_INET_NETOF_FREESTANDING
    errno = E2BIG;
#endif
    if (inet_netof(address) != expected)
        return 0;
#ifndef CRABC_INET_NETOF_FREESTANDING
    if (errno != E2BIG)
        return 0;
#endif
    return 1;
}

static int check_netof(in_addr_t raw, in_addr_t expected)
{
    return check_address(address_from_raw(raw), expected);
}

int crabc_x86_64_inet_netof_probe(void)
{
    if (!check_netof(0x00000000, 0x00000000))
        return 10;
    if (!check_netof(0x7effffff, 0x0000007e))
        return 11;
    if (!check_netof(0x7f123456, 0x0000007f))
        return 12;
    if (!check_netof(0x7fffffff, 0x0000007f))
        return 13;
    if (!check_netof(0x80000000, 0x00008000))
        return 14;
    if (!check_netof(0x80123456, 0x00008012))
        return 15;
    if (!check_netof(0xbfabcdef, 0x0000bfab))
        return 16;
    if (!check_netof(0xbfffffff, 0x0000bfff))
        return 17;
    if (!check_netof(0xc0000000, 0x00c00000))
        return 18;
    if (!check_netof(0xc0123456, 0x00c01234))
        return 19;
    if (!check_netof(0xffffffff, 0x00ffffff))
        return 20;

    /* inet_netof classifies the raw word, not the first network octet. */
    if (!check_address(address_from_octets(10, 1, 2, 192), 0x00c00201))
        return 21;
    if (!check_address(address_from_octets(192, 1, 2, 10), 0x0000000a))
        return 22;

    return 0;
}

#ifndef CRABC_INET_NETOF_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_netof_probe();
}
#endif
