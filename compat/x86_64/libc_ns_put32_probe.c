/* Static crabc-libc x86-64 ns_put32 differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted ns_put32
 * object. It writes only four caller-owned DNS wire bytes at a time; it does
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

typedef void (*ns_put32_signature)(unsigned long, unsigned char *);

_Static_assert(sizeof(unsigned long) == 8, "x86 C unsigned long ABI");
_Static_assert(NS_INT32SZ == 4 && NS_CMPRSFLGS == 0xc0,
    "nameserver wire constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_put32), ns_put32_signature),
    "ns_put32 declaration");

static ns_put32_signature ns_put32_function = ns_put32;

int crabc_x86_64_ns_put32_probe(void)
{
    unsigned char direct[] = {0xa5, 0, 0, 0, 0, 0x5a};
    unsigned char high_bits[] = {0x5a, 0, 0, 0, 0, 0xa5};
    unsigned char macro_bytes[] = {0xb6, 0, 0, 0, 0, 0x6b};
    unsigned char *cursor = macro_bytes + 1;

    ns_put32_function(0x1234abcdUL, direct + 1);
    if (direct[0] != 0xa5 || direct[1] != 0x12 || direct[2] != 0x34 ||
        direct[3] != 0xab || direct[4] != 0xcd || direct[5] != 0x5a)
        return 1;

    ns_put32_function(0x1122334455667788UL, high_bits + 1);
    if (high_bits[0] != 0x5a || high_bits[1] != 0x55 ||
        high_bits[2] != 0x66 || high_bits[3] != 0x77 ||
        high_bits[4] != 0x88 || high_bits[5] != 0xa5)
        return 2;

    NS_PUT32(0xabcdffeeUL, cursor);
    if (macro_bytes[0] != 0xb6 || macro_bytes[1] != 0xab ||
        macro_bytes[2] != 0xcd || macro_bytes[3] != 0xff ||
        macro_bytes[4] != 0xee || macro_bytes[5] != 0x6b ||
        cursor != macro_bytes + 5)
        return 3;

    return 0;
}

#ifndef CRABC_NS_PUT32_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_put32_probe();
}
#endif
