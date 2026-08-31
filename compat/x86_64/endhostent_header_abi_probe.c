/* Pinned-musl/project Linux/x86-64 legacy netdb terminator declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef void (*endhostent_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endhostent),
                                             endhostent_signature),
               "endhostent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endnetent),
                                             endhostent_signature),
               "endnetent declaration");

static endhostent_signature endhostent_function __attribute__((used)) =
    endhostent;
static endhostent_signature endnetent_function __attribute__((used)) =
    endnetent;

int crabc_x86_64_endhostent_header_abi_probe(void)
{
    return endhostent_function == endnetent_function ? 0 : 1;
}
