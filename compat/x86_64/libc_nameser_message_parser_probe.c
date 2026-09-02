/* Static crabc-libc x86-64 nameserver message-parser differential.
 *
 * The same project-header C body runs through pinned musl 1.2.6 and a true
 * `-nostdlib -static` crabc candidate. It selects only ns_initparse,
 * ns_parserr, and ns_name_uncompress over caller-owned DNS wire, ns_msg, and
 * ns_rr storage. Existing dn_expand/ns_skiprr/ns_get16/ns_get32 and initial
 * TLS errno are dependency closure only; no resolver state, DNS I/O, socket,
 * netdb, allocation, or general parser framework is selected.
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

typedef int (*ns_initparse_signature)(const unsigned char *, int, ns_msg *);
typedef int (*ns_parserr_signature)(ns_msg *, ns_sect, int, ns_rr *);
typedef int (*ns_name_uncompress_signature)(const unsigned char *,
    const unsigned char *, const unsigned char *, char *, size_t);

_Static_assert(sizeof(ns_sect) == 4 && _Alignof(ns_sect) == 4,
    "x86 nameserver section enum ABI");
_Static_assert(sizeof(ns_msg) == 80 && _Alignof(ns_msg) == 8,
    "x86 nameserver message ABI");
_Static_assert(offsetof(ns_msg, _msg) == 0 && offsetof(ns_msg, _eom) == 8 &&
    offsetof(ns_msg, _id) == 16 && offsetof(ns_msg, _flags) == 18 &&
    offsetof(ns_msg, _counts) == 20 && offsetof(ns_msg, _sections) == 32 &&
    offsetof(ns_msg, _sect) == 64 && offsetof(ns_msg, _rrnum) == 68 &&
    offsetof(ns_msg, _msg_ptr) == 72, "x86 nameserver message offsets");
_Static_assert(sizeof(ns_rr) == 1048 && _Alignof(ns_rr) == 8,
    "x86 nameserver resource-record ABI");
_Static_assert(offsetof(ns_rr, name) == 0 && offsetof(ns_rr, type) == 1026 &&
    offsetof(ns_rr, rr_class) == 1028 && offsetof(ns_rr, ttl) == 1032 &&
    offsetof(ns_rr, rdlength) == 1036 && offsetof(ns_rr, rdata) == 1040,
    "x86 nameserver resource-record offsets");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_initparse), ns_initparse_signature),
    "ns_initparse declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_parserr), ns_parserr_signature),
    "ns_parserr declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ns_name_uncompress),
    ns_name_uncompress_signature), "ns_name_uncompress declaration");
_Static_assert(ns_s_qd == 0 && ns_s_an == 1 && ns_s_max == 4 &&
    NS_HFIXEDSZ == 12 && NS_QFIXEDSZ == 4 && NS_RRFIXEDSZ == 10 &&
    NS_MAXDNAME == 1025, "nameserver parser constants");

static const ns_initparse_signature ns_initparse_function = ns_initparse;
static const ns_parserr_signature ns_parserr_function = ns_parserr;
static const ns_name_uncompress_signature ns_name_uncompress_function =
    ns_name_uncompress;

static const unsigned char one_answer_message[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1,
};

static const unsigned char two_answer_message[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1,
    0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
};

static void copy_bytes(unsigned char *destination, const unsigned char *source,
    size_t count)
{
    while (count--)
        *destination++ = *source++;
}

static int text_equals(const char *left, const char *right)
{
    while (*left || *right) {
        if (*left++ != *right++)
            return 0;
    }
    return 1;
}

static int check_question(const ns_rr *record)
{
    return !text_equals(ns_rr_name(*record), "www.example.com") ||
        ns_rr_type(*record) != ns_t_a || ns_rr_class(*record) != ns_c_in ||
        ns_rr_ttl(*record) != 0 || ns_rr_rdlen(*record) != 0 ||
        ns_rr_rdata(*record) != 0;
}

static int check_first_answer(const ns_rr *record)
{
    return !text_equals(ns_rr_name(*record), "www.example.com") ||
        ns_rr_type(*record) != ns_t_a || ns_rr_class(*record) != ns_c_in ||
        ns_rr_ttl(*record) != 300 || ns_rr_rdlen(*record) != 4 ||
        !ns_rr_rdata(*record) || record->rdata[0] != 192 ||
        record->rdata[1] != 0 || record->rdata[2] != 2 ||
        record->rdata[3] != 1;
}

static int check_second_answer(const ns_rr *record)
{
    return !text_equals(ns_rr_name(*record), "www.example.com") ||
        ns_rr_type(*record) != ns_t_aaaa || ns_rr_class(*record) != ns_c_in ||
        ns_rr_ttl(*record) != 60 || ns_rr_rdlen(*record) != 16 ||
        !ns_rr_rdata(*record) || record->rdata[0] != 0x20 ||
        record->rdata[1] != 0x01 || record->rdata[2] != 0x0d ||
        record->rdata[3] != 0xb8 || record->rdata[15] != 1;
}

int crabc_x86_64_nameser_message_parser_probe(void)
{
    unsigned char packet[96];
    char name[NS_MAXDNAME];
    ns_msg message;
    ns_rr record;
    const unsigned char *question;
    const unsigned char *first_answer;
    const unsigned char *second_answer;
    const unsigned char *end_of_message;

    copy_bytes(packet, two_answer_message, sizeof(two_answer_message));
    question = packet + NS_HFIXEDSZ;
    first_answer = question + 21;
    second_answer = first_answer + 16;
    end_of_message = packet + sizeof(two_answer_message);

    errno = E2BIG;
    if (ns_initparse_function(packet, sizeof(two_answer_message), &message) != 0 ||
        errno != E2BIG)
        return 1;
    if (message._msg != packet || message._eom != end_of_message ||
        message._id != 0x1234 || message._flags != 0x8180 ||
        message._counts[ns_s_qd] != 1 || message._counts[ns_s_an] != 2 ||
        message._counts[ns_s_ns] != 0 || message._counts[ns_s_ar] != 0 ||
        message._sections[ns_s_qd] != question ||
        message._sections[ns_s_an] != first_answer ||
        message._sections[ns_s_ns] != 0 || message._sections[ns_s_ar] != 0 ||
        message._sect != ns_s_max || message._rrnum != -1 || message._msg_ptr != 0)
        return 2;

    if (ns_parserr_function(&message, ns_s_qd, 0, &record) != 0 ||
        check_question(&record) || errno != E2BIG)
        return 3;
    /* Direct record 1 selection requires musl's selected ns_skiprr advance. */
    if (ns_parserr_function(&message, ns_s_an, 1, &record) != 0 ||
        check_second_answer(&record))
        return 4;
    /* A lower explicit index resets the caller-owned parse cursor. */
    if (ns_parserr_function(&message, ns_s_an, 0, &record) != 0 ||
        check_first_answer(&record))
        return 5;
    /* -1 resumes from the parser's stored record index. */
    if (ns_parserr_function(&message, ns_s_an, -1, &record) != 0 ||
        check_second_answer(&record))
        return 6;
    errno = E2BIG;
    if (ns_name_uncompress_function(packet, end_of_message, second_answer,
            name, sizeof(name)) != 2 || !text_equals(name, "www.example.com") ||
        errno != E2BIG)
        return 7;

    errno = 0;
    if (ns_parserr_function(&message, ns_s_an, 2, &record) != -1 || errno != ENODEV)
        return 8;
    errno = 0;
    if (ns_parserr_function(&message, ns_s_max, 0, &record) != -1 || errno != ENODEV)
        return 9;
    errno = 0;
    if (ns_parserr_function(&message, ns_s_an, -2, &record) != -1 || errno != ENODEV)
        return 10;

    copy_bytes(packet, one_answer_message, sizeof(one_answer_message));
    errno = 0;
    if (ns_initparse_function(packet, NS_HFIXEDSZ - 1, &message) != -1 ||
        errno != EMSGSIZE)
        return 11;
    errno = 0;
    if (ns_initparse_function(packet, sizeof(one_answer_message) - 1, &message) != -1 ||
        errno != EMSGSIZE)
        return 12;
    packet[sizeof(one_answer_message)] = 0;
    errno = 0;
    if (ns_initparse_function(packet, sizeof(one_answer_message) + 1, &message) != -1 ||
        errno != EMSGSIZE)
        return 13;

    copy_bytes(packet, one_answer_message, sizeof(one_answer_message));
    first_answer = packet + NS_HFIXEDSZ + 21;
    end_of_message = packet + sizeof(one_answer_message);
    if (ns_initparse_function(packet, sizeof(one_answer_message), &message) != 0)
        return 14;
    packet[NS_HFIXEDSZ + 21 + 10] = 0;
    packet[NS_HFIXEDSZ + 21 + 11] = 5;
    errno = 0;
    if (ns_parserr_function(&message, ns_s_an, 0, &record) != -1 || errno != EMSGSIZE)
        return 15;

    copy_bytes(packet, one_answer_message, sizeof(one_answer_message));
    if (ns_initparse_function(packet, sizeof(one_answer_message), &message) != 0)
        return 16;
    packet[NS_HFIXEDSZ + 21] = 0xc0;
    packet[NS_HFIXEDSZ + 21 + 1] = 0xff;
    errno = 0;
    if (ns_parserr_function(&message, ns_s_an, 0, &record) != -1 || errno != EMSGSIZE)
        return 17;
    errno = 0;
    if (ns_name_uncompress_function(packet, end_of_message, first_answer,
            name, sizeof(name)) != -1 || errno != EMSGSIZE)
        return 18;
    errno = 0;
    if (ns_name_uncompress_function(packet, end_of_message, packet + NS_HFIXEDSZ,
            name, 0) != -1 || errno != EMSGSIZE)
        return 19;

    return 0;
}

#ifndef CRABC_NAMESER_MESSAGE_PARSER_FREESTANDING
int main(void)
{
    return crabc_x86_64_nameser_message_parser_probe();
}
#endif
