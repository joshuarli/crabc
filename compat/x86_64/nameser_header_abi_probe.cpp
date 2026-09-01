/* C++ companion for the x86-64 <resolv.h> selected nameserver ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

using dn_skipname_signature = int (*)(const unsigned char *,
    const unsigned char *);
using dn_expand_signature = int (*)(const unsigned char *,
    const unsigned char *, const unsigned char *, char *, int);
using ns_flagdata_pointer = const struct _ns_flagdata *;
using ns_get16_signature = unsigned (*)(const unsigned char *);
using ns_get32_signature = unsigned long (*)(const unsigned char *);
using ns_put16_signature = void (*)(unsigned, unsigned char *);
using ns_put32_signature = void (*)(unsigned long, unsigned char *);
using ns_skiprr_signature = int (*)(const unsigned char *, const unsigned char *,
    ns_sect, int);

static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name C++ constants");
#ifndef ns_t_qt_p
#error "musl DNS query-type helper is missing"
#endif
#ifndef ns_t_mrr_p
#error "musl DNS meta-record helper is missing"
#endif
#ifndef ns_t_rr_p
#error "musl DNS resource-record helper is missing"
#endif
#ifndef ns_t_udp_p
#error "musl DNS UDP-transfer helper is missing"
#endif
#ifndef ns_t_xfr_p
#error "musl DNS transfer-type helper is missing"
#endif
#ifndef NS_NXT_BIT_SET
#error "musl DNS next-bit setter is missing"
#endif
#ifndef NS_NXT_BIT_CLEAR
#error "musl DNS next-bit clearer is missing"
#endif
#ifndef NS_NXT_BIT_ISSET
#error "musl DNS next-bit tester is missing"
#endif
static_assert(ns_t_zxfr == 256, "musl DNS ZXFR record type value");
static_assert(ns_t_qt_p(ns_t_axfr) && ns_t_qt_p(ns_t_ixfr) &&
    ns_t_qt_p(ns_t_zxfr) && ns_t_qt_p(ns_t_any) && !ns_t_qt_p(ns_t_opt),
    "musl DNS query-type C++ classification");
static_assert(ns_t_mrr_p(ns_t_tsig) && ns_t_mrr_p(ns_t_opt) &&
    !ns_t_mrr_p(ns_t_a), "musl DNS meta-record C++ classification");
static_assert(ns_t_rr_p(ns_t_a) && !ns_t_rr_p(ns_t_opt) &&
    !ns_t_rr_p(ns_t_axfr), "musl DNS resource-record C++ classification");
static_assert(ns_t_udp_p(ns_t_ixfr) && !ns_t_udp_p(ns_t_axfr) &&
    !ns_t_udp_p(ns_t_zxfr), "musl DNS UDP-transfer C++ classification");

static int crabc_x86_64_nameser_record_macro_probe_cpp()
{
    unsigned char bits[2] = {};

    NS_NXT_BIT_SET(9, bits);
    if (bits[0] != 0 || bits[1] != 0x40 || NS_NXT_BIT_ISSET(9, bits) != 0x40)
        return 1;
    NS_NXT_BIT_CLEAR(9, bits);
    return bits[0] != 0 || bits[1] != 0 || NS_NXT_BIT_ISSET(9, bits) != 0;
}
static_assert(__is_same(decltype(&dn_skipname), dn_skipname_signature),
    "dn_skipname C++ declaration");
static_assert(__is_same(decltype(&dn_expand), dn_expand_signature),
    "dn_expand C++ declaration");
static_assert(sizeof(struct _ns_flagdata) == 8 &&
    alignof(struct _ns_flagdata) == 4,
    "nameserver flag-data C++ layout");
static_assert(offsetof(struct _ns_flagdata, mask) == 0 &&
    offsetof(struct _ns_flagdata, shift) == 4,
    "nameserver flag-data C++ offsets");
static_assert(__is_same(decltype(_ns_flagdata + 0), ns_flagdata_pointer),
    "_ns_flagdata C++ declaration");
static_assert(__is_same(decltype(&ns_get16), ns_get16_signature),
    "ns_get16 C++ declaration");
static_assert(__is_same(decltype(&ns_get32), ns_get32_signature),
    "ns_get32 C++ declaration");
static_assert(__is_same(decltype(&ns_put16), ns_put16_signature),
    "ns_put16 C++ declaration");
static_assert(__is_same(decltype(&ns_put32), ns_put32_signature),
    "ns_put32 C++ declaration");
static_assert(__is_same(decltype(&ns_skiprr), ns_skiprr_signature),
    "ns_skiprr C++ declaration");

static dn_skipname_signature dn_skipname_function = dn_skipname;
static dn_expand_signature dn_expand_function = dn_expand;
static ns_flagdata_pointer ns_flagdata_table = _ns_flagdata;
static ns_get16_signature ns_get16_function = ns_get16;
static ns_get32_signature ns_get32_function = ns_get32;
static ns_put16_signature ns_put16_function = ns_put16;
static ns_put32_signature ns_put32_function = ns_put32;
static ns_skiprr_signature ns_skiprr_function = ns_skiprr;

extern "C" int dn_skipname(const unsigned char *, const unsigned char *);
extern "C" int dn_expand(const unsigned char *, const unsigned char *,
    const unsigned char *, char *, int);
extern "C" const struct _ns_flagdata _ns_flagdata[];
extern "C" unsigned ns_get16(const unsigned char *);
extern "C" unsigned long ns_get32(const unsigned char *);
extern "C" void ns_put16(unsigned, unsigned char *);
extern "C" void ns_put32(unsigned long, unsigned char *);
extern "C" int ns_skiprr(const unsigned char *, const unsigned char *, ns_sect, int);

int crabc_x86_64_nameser_header_abi_probe_cpp()
{
    return dn_skipname_function == &dn_skipname && dn_expand_function == &dn_expand &&
        ns_flagdata_table == _ns_flagdata &&
        ns_get16_function == &ns_get16 &&
        ns_get32_function == &ns_get32 && ns_put16_function == &ns_put16 &&
        ns_put32_function == &ns_put32 && ns_skiprr_function == &ns_skiprr ? 0 : 1;
}
