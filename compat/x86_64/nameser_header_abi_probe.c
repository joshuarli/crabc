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

_Static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name constants");
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

static dn_skipname_signature dn_skipname_function = dn_skipname;
static dn_expand_signature dn_expand_function = dn_expand;
static ns_flagdata_pointer ns_flagdata_table = _ns_flagdata;
static ns_get16_signature ns_get16_function = ns_get16;
static ns_get32_signature ns_get32_function = ns_get32;
static ns_put16_signature ns_put16_function = ns_put16;
static ns_put32_signature ns_put32_function = ns_put32;

int crabc_x86_64_nameser_header_abi_probe(void)
{
    return dn_skipname_function == &dn_skipname && dn_expand_function == &dn_expand &&
        ns_flagdata_table == _ns_flagdata &&
        ns_get16_function == &ns_get16 &&
        ns_get32_function == &ns_get32 && ns_put16_function == &ns_put16 &&
        ns_put32_function == &ns_put32 ? 0 : 1;
}
