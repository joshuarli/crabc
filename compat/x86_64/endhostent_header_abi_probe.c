/* Pinned-musl/project Linux/x86-64 legacy netdb terminator declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef void (*endhostent_signature)(void);
typedef void (*sethostent_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endhostent),
                                             endhostent_signature),
               "endhostent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endnetent),
                                             endhostent_signature),
               "endnetent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sethostent),
                                             sethostent_signature),
               "sethostent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setnetent),
                                             sethostent_signature),
               "setnetent declaration");

static endhostent_signature endhostent_function __attribute__((used)) =
    endhostent;
static endhostent_signature endnetent_function __attribute__((used)) =
    endnetent;
static sethostent_signature sethostent_function __attribute__((used)) =
    sethostent;
static sethostent_signature setnetent_function __attribute__((used)) =
    setnetent;

int crabc_x86_64_endhostent_header_abi_probe(void)
{
    return endhostent_function == endnetent_function &&
            sethostent_function != 0 && setnetent_function != 0
        ? 0
        : 1;
}
