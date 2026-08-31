/* Static crabc-libc x86-64 DNS resource-record span differential.
 *
 * The same project-header C body runs through pinned musl 1.2.6 and through
 * a true `-nostdlib -static` crabc candidate. The selected `ns_skiprr` walks
 * caller-owned question or resource-record bytes through the already selected
 * dn_skipname/ns_get16 primitives and the initial-TLS errno slot. It does not
 * select a DNS parser, DNS I/O, resolver state/configuration, hosts, netdb,
 * sockets, or name expansion/compression.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <resolv.h>
#include <stddef.h>
#include <stdint.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef int (*ns_skiprr_signature)(const unsigned char *,
    const unsigned char *, ns_sect, int);

_Static_assert(sizeof(ns_sect) == 4 && _Alignof(ns_sect) == 4,
    "x86 nameserver section enum ABI");
_Static_assert(ns_s_qd == 0 && ns_s_an == 1 && NS_QFIXEDSZ == 4 &&
    NS_RRFIXEDSZ == 10 && NS_INT16SZ == 2 && NS_INT32SZ == 4,
    "nameserver resource-record wire constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_skiprr), ns_skiprr_signature),
    "ns_skiprr declaration");

static const ns_skiprr_signature ns_skiprr_function = ns_skiprr;

static const unsigned char questions[] = {
    3, 'w', 'w', 'w', 0, 0, 1, 0, 1,
    0, 0, 28, 0, 1,
};

static const unsigned char answers[] = {
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
    0, 0, 28, 0, 1, 0, 0, 0, 0, 0, 0,
};

static const unsigned char truncated_name[] = { 3, 'w', 'w' };
static const unsigned char truncated_question[] = { 0, 0, 1, 0 };
static const unsigned char truncated_rr_fixed[] = {
    0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
};
static const unsigned char truncated_rdata[] = {
    0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0,
};

static int expect_malformed(const unsigned char *first,
    const unsigned char *end, ns_sect section)
{
    errno = E2BIG;
    return ns_skiprr_function(first, end, section, 1) != -1 || errno != EMSGSIZE;
}

int crabc_x86_64_ns_skiprr_probe(void)
{
    errno = E2BIG;
    if (ns_skiprr_function(questions + 5, questions + sizeof(questions),
            ns_s_qd, 0) != 0 || errno != E2BIG)
        return 1;
    if (ns_skiprr_function(questions, questions + sizeof(questions),
            ns_s_qd, 1) != 9)
        return 2;
    if (ns_skiprr_function(questions, questions + sizeof(questions),
            ns_s_qd, 2) != (int)sizeof(questions))
        return 3;
    if (ns_skiprr_function(answers, answers + sizeof(answers),
            ns_s_an, 1) != 16)
        return 4;
    if (ns_skiprr_function(answers, answers + sizeof(answers),
            ns_s_an, 2) != (int)sizeof(answers))
        return 5;
    if (expect_malformed(truncated_name,
            truncated_name + sizeof(truncated_name), ns_s_qd))
        return 6;
    if (expect_malformed(truncated_question,
            truncated_question + sizeof(truncated_question), ns_s_qd))
        return 7;
    if (expect_malformed(truncated_rr_fixed,
            truncated_rr_fixed + sizeof(truncated_rr_fixed), ns_s_an))
        return 8;
    if (expect_malformed(truncated_rdata,
            truncated_rdata + sizeof(truncated_rdata), ns_s_an))
        return 9;
    return 0;
}

#ifndef CRABC_NS_SKIPRR_FREESTANDING
int main(void)
{
    return crabc_x86_64_ns_skiprr_probe();
}
#endif
