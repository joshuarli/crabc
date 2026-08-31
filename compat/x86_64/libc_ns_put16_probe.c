/* Static crabc-libc x86-64 ns_put16 differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted ns_put16
 * object. It writes only two caller-owned DNS wire bytes at a time; it does
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

typedef void (*ns_put16_signature)(unsigned, unsigned char *);

_Static_assert(sizeof(unsigned) == 4, "x86 C unsigned ABI");
_Static_assert(NS_INT16SZ == 2 && NS_CMPRSFLGS == 0xc0,
    "nameserver wire constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_put16), ns_put16_signature),
    "ns_put16 declaration");

static ns_put16_signature ns_put16_function = ns_put16;

int crabc_x86_64_ns_put16_probe(void)
{
    unsigned char direct[] = { 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf };
    unsigned char macro_bytes[] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
    unsigned char *cursor = macro_bytes + 1;

    ns_put16_function(0x1234U, direct + 1);
    if (direct[0] != 0x5a || direct[1] != 0x12 || direct[2] != 0x34 ||
        direct[3] != 0x8d || direct[4] != 0x9e || direct[5] != 0xaf)
        return 1;

    ns_put16_function(0xbeefcafeU, direct + 3);
    if (direct[0] != 0x5a || direct[1] != 0x12 || direct[2] != 0x34 ||
        direct[3] != 0xca || direct[4] != 0xfe || direct[5] != 0xaf)
        return 2;

    NS_PUT16(0xdeadU, cursor);
    if (cursor != macro_bytes + 3)
        return 3;
    if (macro_bytes[0] != 0x11 || macro_bytes[1] != 0xde ||
        macro_bytes[2] != 0xad || macro_bytes[3] != 0x44 ||
        macro_bytes[4] != 0x55)
        return 4;

    return 0;
}

#ifndef CRABC_NS_PUT16_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_put16_probe();
}
#endif
