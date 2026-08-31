/* Static C IPv4 classful-address differential. */
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

typedef struct in_addr (*inet_makeaddr_signature)(in_addr_t, in_addr_t);
typedef in_addr_t (*inet_lnaof_signature)(struct in_addr);

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4,
    "x86 in_addr_t layout");
_Static_assert(sizeof(struct in_addr) == 4, "x86 in_addr layout");
_Static_assert(_Alignof(struct in_addr) == 4, "x86 in_addr alignment");
_Static_assert(offsetof(struct in_addr, s_addr) == 0, "x86 in_addr offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_makeaddr),
    inet_makeaddr_signature), "inet_makeaddr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_lnaof),
    inet_lnaof_signature), "inet_lnaof declaration");

static struct in_addr address_from_raw(in_addr_t raw)
{
    struct in_addr address;

    address.s_addr = raw;
    return address;
}

static int check_makeaddr(in_addr_t network, in_addr_t host, in_addr_t expected)
{
    return inet_makeaddr(network, host).s_addr == expected;
}

static int check_lnaof(in_addr_t raw, in_addr_t expected)
{
    return inet_lnaof(address_from_raw(raw)) == expected;
}

int crabc_x86_64_inet_classful_probe(void)
{
    if (!check_makeaddr(127, 0x00123456, 0x7f123456))
        return 10;
    if (!check_makeaddr(128, 0x00003456, 0x80003456))
        return 11;
    if (!check_makeaddr(256, 0x00003456, 0x01003456))
        return 12;
    if (!check_makeaddr(65535, 0x000000aa, 0xffff00aa))
        return 13;
    if (!check_makeaddr(65536, 0x000000bb, 0x010000bb))
        return 14;
    /* Musl ORs rather than masking the caller-supplied host value. */
    if (!check_makeaddr(256, 0xff000001, 0xff000001))
        return 15;

    if (!check_lnaof(0x7f123456, 0x00123456))
        return 20;
    if (!check_lnaof(0x80123456, 0x00003456))
        return 21;
    if (!check_lnaof(0xbfabcdef, 0x0000cdef))
        return 22;
    if (!check_lnaof(0xc0123456, 0x00000056))
        return 23;
    if (!check_lnaof(0xffffffff, 0x000000ff))
        return 24;
    if (inet_lnaof(inet_makeaddr(127, 0x00123456)) != 0x00123456)
        return 25;

    return 0;
}

#ifndef CRABC_INET_CLASSFUL_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_classful_probe();
}
#endif
