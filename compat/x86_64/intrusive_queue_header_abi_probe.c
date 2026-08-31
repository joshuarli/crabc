/* Source-only Linux/x86-64 search.h insque/remque declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <search.h>

typedef void (*insque_signature)(void *, void *);
typedef void (*remque_signature)(void *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&insque),
    insque_signature), "insque declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&remque),
    remque_signature), "remque declaration");

static insque_signature insque_function __attribute__((used)) = insque;
static remque_signature remque_function __attribute__((used)) = remque;

int crabc_x86_64_intrusive_queue_header_abi_probe(void)
{
    return insque_function != (insque_signature)0 &&
            remque_function != (remque_signature)0 ? 0 : 1;
}
