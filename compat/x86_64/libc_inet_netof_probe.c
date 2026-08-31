/* Static C IPv4 classful network-part differential. */
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

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

static int check_netof(in_addr_t raw, in_addr_t expected)
{
    return inet_netof(address_from_raw(raw)) == expected;
}

int crabc_x86_64_inet_netof_probe(void)
{
    if (!check_netof(0x00000000, 0x00000000))
        return 10;
    if (!check_netof(0x7f123456, 0x0000007f))
        return 11;
    if (!check_netof(0x80123456, 0x00008012))
        return 12;
    if (!check_netof(0xbfabcdef, 0x0000bfab))
        return 13;
    if (!check_netof(0xc0123456, 0x00c01234))
        return 14;
    if (!check_netof(0xffffffff, 0x00ffffff))
        return 15;

    return 0;
}

#ifndef CRABC_INET_NETOF_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_netof_probe();
}
#endif
