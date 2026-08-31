/* C++ companion for the x86-64 <resolv.h> dn_skipname ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>

using dn_skipname_signature = int (*)(const unsigned char *,
    const unsigned char *);

static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name C++ constants");
static_assert(__is_same(decltype(&dn_skipname), dn_skipname_signature),
    "dn_skipname C++ declaration");

static dn_skipname_signature dn_skipname_function = dn_skipname;

extern "C" int dn_skipname(const unsigned char *, const unsigned char *);

int crabc_x86_64_nameser_header_abi_probe_cpp()
{
    return dn_skipname_function == &dn_skipname ? 0 : 1;
}
