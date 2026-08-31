/* Static crabc-libc x86-64 _ns_flagdata differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted _ns_flagdata
 * object. It proves nameser macro data only, not DNS parsing, resolver state,
 * resolver files, DNS I/O, sockets, netdb, or an adjacent parser helper.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/nameser.h>
#include <stddef.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef const struct _ns_flagdata *ns_flagdata_pointer;

_Static_assert(sizeof(struct _ns_flagdata) == 8 &&
    _Alignof(struct _ns_flagdata) == 4,
    "x86 nameserver flag-data ABI");
_Static_assert(offsetof(struct _ns_flagdata, mask) == 0 &&
    offsetof(struct _ns_flagdata, shift) == 4,
    "nameserver flag-data member offsets");
_Static_assert(CRABC_TYPE_IS(__typeof__(_ns_flagdata + 0),
    ns_flagdata_pointer), "_ns_flagdata declaration");

static const struct _ns_flagdata expected[16] = {
    { 0x8000, 15 }, { 0x7800, 11 }, { 0x0400, 10 }, { 0x0200, 9 },
    { 0x0100, 8 }, { 0x0080, 7 }, { 0x0040, 6 }, { 0x0020, 5 },
    { 0x0010, 4 }, { 0x000f, 0 }, { 0, 0 }, { 0, 0 },
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 },
};

static int table_matches(const volatile struct _ns_flagdata *table)
{
    for (size_t index = 0; index < 16; index++) {
        if (table[index].mask != expected[index].mask ||
            table[index].shift != expected[index].shift)
            return 0;
    }
    return 1;
}

static int flags_match(unsigned short flags, unsigned qr, unsigned opcode,
    unsigned aa, unsigned tc, unsigned rd, unsigned ra, unsigned z,
    unsigned ad, unsigned cd, unsigned rcode)
{
    ns_msg message = { 0 };

    message._flags = flags;
    return ns_msg_getflag(message, ns_f_qr) == qr &&
        ns_msg_getflag(message, ns_f_opcode) == opcode &&
        ns_msg_getflag(message, ns_f_aa) == aa &&
        ns_msg_getflag(message, ns_f_tc) == tc &&
        ns_msg_getflag(message, ns_f_rd) == rd &&
        ns_msg_getflag(message, ns_f_ra) == ra &&
        ns_msg_getflag(message, ns_f_z) == z &&
        ns_msg_getflag(message, ns_f_ad) == ad &&
        ns_msg_getflag(message, ns_f_cd) == cd &&
        ns_msg_getflag(message, ns_f_rcode) == rcode;
}

int crabc_x86_64_ns_flagdata_probe(void)
{
    const volatile struct _ns_flagdata *first = _ns_flagdata;
    const volatile struct _ns_flagdata *second = _ns_flagdata;

    if (first != second)
        return 1;
    if (!table_matches(first))
        return 2;
    if (!flags_match(0xffff, 1, 15, 1, 1, 1, 1, 1, 1, 1, 15))
        return 3;
    if (!flags_match(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return 4;
    if (!flags_match(0x2905, 0, 5, 0, 0, 1, 0, 0, 0, 0, 5))
        return 5;
    return 0;
}

#ifndef CRABC_NS_FLAGDATA_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_flagdata_probe();
}
#endif
