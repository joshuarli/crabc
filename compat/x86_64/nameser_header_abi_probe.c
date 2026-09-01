/* Native Linux/x86-64 <resolv.h> selected nameserver declaration ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

typedef int (*dn_skipname_signature)(const unsigned char *,
    const unsigned char *);
typedef int (*dn_expand_signature)(const unsigned char *,
    const unsigned char *, const unsigned char *, char *, int);
typedef const struct _ns_flagdata *ns_flagdata_pointer;
typedef unsigned (*ns_get16_signature)(const unsigned char *);
typedef unsigned long (*ns_get32_signature)(const unsigned char *);
typedef void (*ns_put16_signature)(unsigned, unsigned char *);
typedef void (*ns_put32_signature)(unsigned long, unsigned char *);
typedef int (*ns_skiprr_signature)(const unsigned char *, const unsigned char *,
    ns_sect, int);

_Static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name constants");
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
_Static_assert(ns_t_zxfr == 256, "musl DNS ZXFR record type value");
_Static_assert(ns_t_qt_p(ns_t_axfr) && ns_t_qt_p(ns_t_ixfr) &&
    ns_t_qt_p(ns_t_zxfr) && ns_t_qt_p(ns_t_any) && !ns_t_qt_p(ns_t_opt),
    "musl DNS query-type classification");
_Static_assert(ns_t_mrr_p(ns_t_tsig) && ns_t_mrr_p(ns_t_opt) &&
    !ns_t_mrr_p(ns_t_a), "musl DNS meta-record classification");
_Static_assert(ns_t_rr_p(ns_t_a) && !ns_t_rr_p(ns_t_opt) &&
    !ns_t_rr_p(ns_t_axfr), "musl DNS resource-record classification");
_Static_assert(ns_t_udp_p(ns_t_ixfr) && !ns_t_udp_p(ns_t_axfr) &&
    !ns_t_udp_p(ns_t_zxfr), "musl DNS UDP-transfer classification");

#ifdef CRABC_NAMESER_RECORD_MACRO_RUNTIME
int main(void)
{
    unsigned char bits[2] = {0};

    NS_NXT_BIT_SET(9, bits);
    if (bits[0] != 0 || bits[1] != 0x40 || NS_NXT_BIT_ISSET(9, bits) != 0x40)
        return 1;
    NS_NXT_BIT_CLEAR(9, bits);
    return bits[0] != 0 || bits[1] != 0 || NS_NXT_BIT_ISSET(9, bits) != 0;
}
#else
_Static_assert(__builtin_types_compatible_p(__typeof__(&dn_skipname),
    dn_skipname_signature), "dn_skipname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dn_expand),
    dn_expand_signature), "dn_expand declaration");
_Static_assert(sizeof(struct _ns_flagdata) == 8 &&
    _Alignof(struct _ns_flagdata) == 4,
    "nameserver flag-data layout");
_Static_assert(offsetof(struct _ns_flagdata, mask) == 0 &&
    offsetof(struct _ns_flagdata, shift) == 4,
    "nameserver flag-data offsets");
_Static_assert(__builtin_types_compatible_p(__typeof__(_ns_flagdata + 0),
    ns_flagdata_pointer), "_ns_flagdata declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ns_get16),
    ns_get16_signature), "ns_get16 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ns_get32),
    ns_get32_signature), "ns_get32 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ns_put16),
    ns_put16_signature), "ns_put16 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ns_put32),
    ns_put32_signature), "ns_put32 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ns_skiprr),
    ns_skiprr_signature), "ns_skiprr declaration");

static dn_skipname_signature dn_skipname_function = dn_skipname;
static dn_expand_signature dn_expand_function = dn_expand;
static ns_flagdata_pointer ns_flagdata_table = _ns_flagdata;
static ns_get16_signature ns_get16_function = ns_get16;
static ns_get32_signature ns_get32_function = ns_get32;
static ns_put16_signature ns_put16_function = ns_put16;
static ns_put32_signature ns_put32_function = ns_put32;
static ns_skiprr_signature ns_skiprr_function = ns_skiprr;

int crabc_x86_64_nameser_header_abi_probe(void)
{
    return dn_skipname_function == &dn_skipname && dn_expand_function == &dn_expand &&
        ns_flagdata_table == _ns_flagdata &&
        ns_get16_function == &ns_get16 &&
        ns_get32_function == &ns_get32 && ns_put16_function == &ns_put16 &&
        ns_put32_function == &ns_put32 && ns_skiprr_function == &ns_skiprr ? 0 : 1;
}
#endif
