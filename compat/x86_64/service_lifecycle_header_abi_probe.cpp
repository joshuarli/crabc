/* C++17 companion for the pinned-musl/project service-lifecycle gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

using getservent_signature = servent *(*)(void);
using setservent_signature = void (*)(int);

static_assert(__is_same(decltype(&getservent), getservent_signature),
              "C++ getservent declaration");
static_assert(__is_same(decltype(&setservent), setservent_signature),
              "C++ setservent declaration");

static getservent_signature getservent_function __attribute__((used)) = getservent;
static setservent_signature setservent_function __attribute__((used)) = setservent;

int crabc_x86_64_service_lifecycle_header_abi_probe_cpp()
{
    return getservent_function == getservent && setservent_function == setservent ? 0 : 1;
}
