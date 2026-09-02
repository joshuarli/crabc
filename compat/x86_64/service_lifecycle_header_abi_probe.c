/* Pinned-musl/project Linux/x86-64 service-lifecycle declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

typedef struct servent *(*getservent_signature)(void);
typedef void (*setservent_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getservent),
                                             getservent_signature),
               "getservent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setservent),
                                             setservent_signature),
               "setservent declaration");

static getservent_signature getservent_function __attribute__((used)) = getservent;
static setservent_signature setservent_function __attribute__((used)) = setservent;

int crabc_x86_64_service_lifecycle_header_abi_probe(void)
{
    return getservent_function == getservent && setservent_function == setservent ? 0 : 1;
}
