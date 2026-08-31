/* C++17 companion for the Linux/x86-64 search.h insque/remque declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <search.h>

using insque_signature = void (*)(void *, void *);
using remque_signature = void (*)(void *);

static_assert(__is_same(decltype(&insque), insque_signature),
    "C++ insque declaration");
static_assert(__is_same(decltype(&remque), remque_signature),
    "C++ remque declaration");

static insque_signature insque_function __attribute__((used)) = insque;
static remque_signature remque_function __attribute__((used)) = remque;

int crabc_x86_64_intrusive_queue_header_abi_probe_cpp()
{
    return insque_function != nullptr && remque_function != nullptr ? 0 : 1;
}
