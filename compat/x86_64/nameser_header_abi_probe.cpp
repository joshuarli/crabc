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
using ns_get16_signature = unsigned (*)(const unsigned char *);
using ns_get32_signature = unsigned long (*)(const unsigned char *);
using ns_put16_signature = void (*)(unsigned, unsigned char *);

static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "musl DNS wire-name C++ constants");
static_assert(__is_same(decltype(&dn_skipname), dn_skipname_signature),
    "dn_skipname C++ declaration");
static_assert(__is_same(decltype(&dn_expand), dn_expand_signature),
    "dn_expand C++ declaration");
static_assert(__is_same(decltype(&ns_get16), ns_get16_signature),
    "ns_get16 C++ declaration");
static_assert(__is_same(decltype(&ns_get32), ns_get32_signature),
    "ns_get32 C++ declaration");
static_assert(__is_same(decltype(&ns_put16), ns_put16_signature),
    "ns_put16 C++ declaration");

static dn_skipname_signature dn_skipname_function = dn_skipname;
static dn_expand_signature dn_expand_function = dn_expand;
static ns_get16_signature ns_get16_function = ns_get16;
static ns_get32_signature ns_get32_function = ns_get32;
static ns_put16_signature ns_put16_function = ns_put16;

extern "C" int dn_skipname(const unsigned char *, const unsigned char *);
extern "C" int dn_expand(const unsigned char *, const unsigned char *,
    const unsigned char *, char *, int);
extern "C" unsigned ns_get16(const unsigned char *);
extern "C" unsigned long ns_get32(const unsigned char *);
extern "C" void ns_put16(unsigned, unsigned char *);

int crabc_x86_64_nameser_header_abi_probe_cpp()
{
    return dn_skipname_function == &dn_skipname && dn_expand_function == &dn_expand &&
        ns_get16_function == &ns_get16 &&
        ns_get32_function == &ns_get32 && ns_put16_function == &ns_put16 ? 0 : 1;
}
