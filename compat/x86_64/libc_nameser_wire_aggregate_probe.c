/* Static crabc-libc x86-64 nameser wire/data aggregate differential.
 *
 * One project-header C transaction runs against pinned musl 1.2.6 and a true
 * `-nostdlib -static` crabc candidate. It builds one unaligned caller-owned
 * DNS response with ns_put16/ns_put32, then consumes it through the selected
 * dn_skipname, dn_expand, _ns_flagdata, ns_get16, ns_get32, and ns_skiprr
 * boundaries. This is a private wire/data composition proof: it selects no
 * resolver configuration, DNS I/O, sockets, netdb, or general DNS parser.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/nameser.h>
#include <errno.h>
#include <resolv.h>
#include <stddef.h>
#include <stdint.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef int (*dn_skipname_signature)(const unsigned char *, const unsigned char *);
typedef int (*dn_expand_signature)(const unsigned char *, const unsigned char *,
    const unsigned char *, char *, int);
typedef unsigned (*ns_get16_signature)(const unsigned char *);
typedef unsigned long (*ns_get32_signature)(const unsigned char *);
typedef void (*ns_put16_signature)(unsigned, unsigned char *);
typedef void (*ns_put32_signature)(unsigned long, unsigned char *);
typedef int (*ns_skiprr_signature)(const unsigned char *, const unsigned char *,
    ns_sect, int);

_Static_assert(NS_HFIXEDSZ == 12 && NS_QFIXEDSZ == 4 && NS_RRFIXEDSZ == 10 &&
    NS_INT16SZ == 2 && NS_INT32SZ == 4, "nameser wire constants");
_Static_assert(sizeof(ns_sect) == 4 && _Alignof(ns_sect) == 4,
    "nameser section enum ABI");
_Static_assert(sizeof(struct _ns_flagdata) == 8 &&
    _Alignof(struct _ns_flagdata) == 4, "nameser flag-data ABI");
_Static_assert(CRABC_TYPE_IS(__typeof__(&dn_skipname), dn_skipname_signature),
    "dn_skipname declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&dn_expand), dn_expand_signature),
    "dn_expand declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_get16), ns_get16_signature),
    "ns_get16 declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_get32), ns_get32_signature),
    "ns_get32 declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_put16), ns_put16_signature),
    "ns_put16 declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_put32), ns_put32_signature),
    "ns_put32 declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_skiprr), ns_skiprr_signature),
    "ns_skiprr declaration");

static const dn_skipname_signature dn_skipname_function = dn_skipname;
static const dn_expand_signature dn_expand_function = dn_expand;
static const ns_get16_signature ns_get16_function = ns_get16;
static const ns_get32_signature ns_get32_function = ns_get32;
static const ns_put16_signature ns_put16_function = ns_put16;
static const ns_put32_signature ns_put32_function = ns_put32;
static const ns_skiprr_signature ns_skiprr_function = ns_skiprr;

static const unsigned char owner_name[] = {
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
};

static int text_equals(const char *actual, const char *expected)
{
    while (*actual == *expected) {
        if (*actual == '\0')
            return 1;
        actual++;
        expected++;
    }
    return 0;
}

static int flags_match(unsigned short flags)
{
    ns_msg message = { 0 };
    const volatile struct _ns_flagdata *table = _ns_flagdata;

    message._flags = flags;
    return table[ns_f_qr].mask == 0x8000 && table[ns_f_qr].shift == 15 &&
        table[ns_f_opcode].mask == 0x7800 &&
        table[ns_f_opcode].shift == 11 &&
        ns_msg_getflag(message, ns_f_qr) == 1 &&
        ns_msg_getflag(message, ns_f_opcode) == 0 &&
        ns_msg_getflag(message, ns_f_aa) == 1 &&
        ns_msg_getflag(message, ns_f_tc) == 0 &&
        ns_msg_getflag(message, ns_f_rd) == 1 &&
        ns_msg_getflag(message, ns_f_ra) == 1 &&
        ns_msg_getflag(message, ns_f_z) == 0 &&
        ns_msg_getflag(message, ns_f_ad) == 0 &&
        ns_msg_getflag(message, ns_f_cd) == 0 &&
        ns_msg_getflag(message, ns_f_rcode) == 0;
}

static int expect_malformed(const unsigned char *first, const unsigned char *end)
{
    errno = E2BIG;
    return ns_skiprr_function(first, end, ns_s_an, 1) != -1 || errno != EMSGSIZE;
}

int crabc_x86_64_nameser_wire_aggregate_probe(void)
{
    unsigned char storage[80];
    unsigned char *message = storage + 1;
    unsigned char *cursor = message;
    const unsigned char *question;
    const unsigned char *answer;
    const unsigned char *eom;
    char expanded[64];

    for (size_t index = 0; index < sizeof(storage); index++)
        storage[index] = 0;

    ns_put16_function(0x1234U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(0x8580U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(0U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(0U, cursor);
    cursor += NS_INT16SZ;

    question = cursor;
    for (size_t index = 0; index < sizeof(owner_name); index++)
        *cursor++ = owner_name[index];
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;

    answer = cursor;
    *cursor++ = 0xc0;
    *cursor++ = 0x0c;
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;
    ns_put16_function(1U, cursor);
    cursor += NS_INT16SZ;
    ns_put32_function(60UL, cursor);
    cursor += NS_INT32SZ;
    ns_put16_function(4U, cursor);
    cursor += NS_INT16SZ;
    *cursor++ = 127;
    *cursor++ = 0;
    *cursor++ = 0;
    *cursor++ = 1;
    eom = cursor;

    if (ns_get16_function(message) != 0x1234U ||
        ns_get16_function(message + 2) != 0x8580U ||
        ns_get16_function(message + 4) != 1U ||
        ns_get16_function(message + 6) != 1U ||
        ns_get16_function(message + 8) != 0U ||
        ns_get16_function(message + 10) != 0U)
        return 1;
    if (!flags_match(ns_get16_function(message + 2)))
        return 2;
    if (ns_get16_function(question + sizeof(owner_name)) != 1U ||
        ns_get16_function(question + sizeof(owner_name) + NS_INT16SZ) != 1U)
        return 3;
    if (ns_get16_function(answer + 2) != 1U ||
        ns_get16_function(answer + 4) != 1U ||
        ns_get32_function(answer + 6) != 60UL ||
        ns_get16_function(answer + 10) != 4U ||
        answer[12] != 127 || answer[13] != 0 || answer[14] != 0 || answer[15] != 1)
        return 4;
    if (eom != message + 49)
        return 5;
    if (dn_skipname_function(question, eom) != (int)sizeof(owner_name) ||
        dn_skipname_function(answer, eom) != 2)
        return 6;
    if (dn_expand_function(message, eom, question, expanded, sizeof(expanded)) !=
            (int)sizeof(owner_name) ||
        !text_equals(expanded, "www.example.com"))
        return 7;
    if (dn_expand_function(message, eom, answer, expanded, sizeof(expanded)) != 2 ||
        !text_equals(expanded, "www.example.com"))
        return 8;
    if (ns_skiprr_function(question, eom, ns_s_qd, 1) !=
        (int)(sizeof(owner_name) + NS_QFIXEDSZ))
        return 9;
    if (ns_skiprr_function(answer, eom, ns_s_an, 1) !=
        (int)(2 + NS_RRFIXEDSZ + 4))
        return 10;
    errno = E2BIG;
    if (ns_skiprr_function(question, eom, ns_s_qd, 0) != 0 || errno != E2BIG)
        return 11;
    if (expect_malformed(answer, eom - 1))
        return 12;
    return 0;
}

#ifndef CRABC_NAMESER_WIRE_AGGREGATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_nameser_wire_aggregate_probe();
}
#endif
