/* Static crabc-libc x86-64 ns_get16 differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted ns_get16
 * object. It reads only two caller-owned DNS wire bytes at a time; it does not
 * select resolver state, resolver files, DNS I/O, sockets, netdb, or a DNS
 * parser.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>
#include <stddef.h>
#include <stdint.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef unsigned (*ns_get16_signature)(const unsigned char *);

_Static_assert(sizeof(unsigned) == 4, "x86 C unsigned ABI");
_Static_assert(NS_INT16SZ == 2 && NS_CMPRSFLGS == 0xc0,
    "nameserver wire constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_get16), ns_get16_signature),
    "ns_get16 declaration");

static ns_get16_signature ns_get16_function = ns_get16;
static const unsigned char octets[] = { 0x00, 0x12, 0x34, 0xab, 0xcd, 0xff };

int crabc_x86_64_ns_get16_probe(void)
{
    const unsigned char *cursor = octets + 1;
    unsigned value = 0;

    if (ns_get16_function(octets) != 0x0012U)
        return 1;
    if (ns_get16_function(octets + 1) != 0x1234U)
        return 2;
    if (ns_get16_function(octets + 2) != 0x34abU)
        return 3;
    if (ns_get16_function(octets + 3) != 0xabcdU)
        return 4;
    if (ns_get16_function(octets + 4) != 0xcdffU)
        return 5;

    NS_GET16(value, cursor);
    if (value != 0x1234U || cursor != octets + 3)
        return 6;
    NS_GET16(value, cursor);
    if (value != 0xabcdU || cursor != octets + 5)
        return 7;
    return 0;
}

#ifndef CRABC_NS_GET16_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_get16_probe();
}
#endif
