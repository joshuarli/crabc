/* Static crabc-libc x86-64 ns_get32 differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted ns_get32
 * object. It reads only four caller-owned DNS wire bytes at a time; it does
 * not select resolver state, resolver files, DNS I/O, sockets, netdb, or a
 * DNS parser.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef unsigned long (*ns_get32_signature)(const unsigned char *);

_Static_assert(sizeof(unsigned long) == 8, "x86 C unsigned long ABI");
_Static_assert(NS_INT32SZ == 4 && NS_CMPRSFLGS == 0xc0,
    "nameserver wire constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_get32), ns_get32_signature),
    "ns_get32 declaration");

static ns_get32_signature ns_get32_function = ns_get32;
static const unsigned char octets[] = {
    0x00, 0x12, 0x34, 0xab, 0xcd, 0xff, 0xee,
};

int crabc_x86_64_ns_get32_probe(void)
{
    const unsigned char *cursor = octets + 1;
    unsigned long value = 0;

    if (ns_get32_function(octets) != 0x001234abUL)
        return 1;
    if (ns_get32_function(octets + 1) != 0x1234abcdUL)
        return 2;
    if (ns_get32_function(octets + 2) != 0x34abcdffUL)
        return 3;
    if (ns_get32_function(octets + 3) != 0xabcdffeeUL)
        return 4;

    NS_GET32(value, cursor);
    if (value != 0x1234abcdUL || cursor != octets + 5)
        return 5;

    return 0;
}

#ifndef CRABC_NS_GET32_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_get32_probe();
}
#endif
