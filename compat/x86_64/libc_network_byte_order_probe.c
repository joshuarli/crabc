/* Static x86-64 network byte-order C ABI and behavior fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through one freestanding executable linked solely with the selected
 * crabc archive. It selects exactly htonl, htons, ntohl, and ntohs: scalar
 * 32-bit and 16-bit host/network byte-order conversion. It deliberately
 * excludes address parsing/formatting, inet_ntoa storage, resolver state,
 * hosts/resolv.conf configuration, DNS, netdb, sockets, interfaces, errno,
 * TLS, allocation, libc.so, CRT, loader, and public x86 support.
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
#include <stdint.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef uint32_t (*network_u32_function)(uint32_t);
typedef uint16_t (*network_u16_function)(uint16_t);

_Static_assert(sizeof(uint32_t) == 4 && _Alignof(uint32_t) == 4,
    "x86 uint32_t width/alignment");
_Static_assert(sizeof(uint16_t) == 2 && _Alignof(uint16_t) == 2,
    "x86 uint16_t width/alignment");
_Static_assert(CRABC_TYPE_IS(__typeof__(&htonl), network_u32_function),
    "htonl declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ntohl), network_u32_function),
    "ntohl declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&htons), network_u16_function),
    "htons declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ntohs), network_u16_function),
    "ntohs declaration");

union wire_u32 {
    uint32_t value;
    unsigned char bytes[4];
};

union wire_u16 {
    uint16_t value;
    unsigned char bytes[2];
};

static const network_u32_function host_to_network_u32 = htonl;
static const network_u32_function network_to_host_u32 = ntohl;
static const network_u16_function host_to_network_u16 = htons;
static const network_u16_function network_to_host_u16 = ntohs;

static int check_u32(void)
{
    const uint32_t host = UINT32_C(0x01020304);
    const uint32_t alternate = UINT32_C(0x89abcdef);
    union wire_u32 wire = { .value = host_to_network_u32(host) };

    if (wire.value != UINT32_C(0x04030201) ||
        wire.bytes[0] != 0x01 || wire.bytes[1] != 0x02 ||
        wire.bytes[2] != 0x03 || wire.bytes[3] != 0x04)
        return 1;
    if (network_to_host_u32(wire.value) != host ||
        network_to_host_u32(host_to_network_u32(alternate)) != alternate)
        return 2;
    if (host_to_network_u32(UINT32_C(0)) != UINT32_C(0) ||
        host_to_network_u32(UINT32_MAX) != UINT32_MAX ||
        network_to_host_u32(UINT32_C(0)) != UINT32_C(0) ||
        network_to_host_u32(UINT32_MAX) != UINT32_MAX)
        return 3;
    return 0;
}

static int check_u16(void)
{
    const uint16_t host = UINT16_C(0x0102);
    const uint16_t alternate = UINT16_C(0x89ab);
    union wire_u16 wire = { .value = host_to_network_u16(host) };

    if (wire.value != UINT16_C(0x0201) ||
        wire.bytes[0] != 0x01 || wire.bytes[1] != 0x02)
        return 1;
    if (network_to_host_u16(wire.value) != host ||
        network_to_host_u16(host_to_network_u16(alternate)) != alternate)
        return 2;
    if (host_to_network_u16(UINT16_C(0)) != UINT16_C(0) ||
        host_to_network_u16(UINT16_MAX) != UINT16_MAX ||
        network_to_host_u16(UINT16_C(0)) != UINT16_C(0) ||
        network_to_host_u16(UINT16_MAX) != UINT16_MAX)
        return 3;
    return 0;
}

int crabc_x86_64_network_byte_order_probe(void)
{
    const int u32_status = check_u32();
    const int u16_status = check_u16();

    if (u32_status != 0)
        return 10 + u32_status;
    return u16_status == 0 ? 0 : 20 + u16_status;
}

#ifndef CRABC_NETWORK_BYTE_ORDER_FREESTANDING
int main(void)
{
    return crabc_x86_64_network_byte_order_probe();
}
#endif
