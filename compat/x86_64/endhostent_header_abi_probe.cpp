/* C++17 companion for the pinned-musl/project legacy netdb terminator gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>

using endhostent_signature = void (*)(void);

static_assert(__is_same(decltype(&endhostent), endhostent_signature),
              "C++ endhostent declaration");
static_assert(__is_same(decltype(&endnetent), endhostent_signature),
              "C++ endnetent declaration");

static endhostent_signature endhostent_function __attribute__((used)) =
    endhostent;
static endhostent_signature endnetent_function __attribute__((used)) =
    endnetent;

int crabc_x86_64_endhostent_header_abi_probe_cpp()
{
    return endhostent_function == endnetent_function ? 0 : 1;
}
