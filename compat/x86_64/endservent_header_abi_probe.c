/* Pinned-musl/project Linux/x86-64 legacy service terminator declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef void (*endservent_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endservent),
                                             endservent_signature),
               "endservent declaration");

static endservent_signature endservent_function __attribute__((used)) =
    endservent;

int crabc_x86_64_endservent_header_abi_probe(void)
{
    return endservent_function == endservent ? 0 : 1;
}
