/* Native Linux/x86-64 <resolv.h> dn_skipname declaration ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

typedef int (*dn_skipname_signature)(const unsigned char *,
    const unsigned char *);

_Static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dn_skipname),
    dn_skipname_signature), "dn_skipname declaration");

static dn_skipname_signature dn_skipname_function = dn_skipname;

int crabc_x86_64_nameser_header_abi_probe(void)
{
    return dn_skipname_function == &dn_skipname ? 0 : 1;
}
