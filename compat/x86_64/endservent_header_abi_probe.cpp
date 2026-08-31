/* C++17 companion for the pinned-musl/project legacy service terminator gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

using endservent_signature = void (*)(void);

static_assert(__is_same(decltype(&endservent), endservent_signature),
              "C++ endservent declaration");

static endservent_signature endservent_function __attribute__((used)) =
    endservent;

int crabc_x86_64_endservent_header_abi_probe_cpp()
{
    return endservent_function == endservent ? 0 : 1;
}
