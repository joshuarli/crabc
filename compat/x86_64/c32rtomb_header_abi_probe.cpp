/* C++17 companion for the Linux/x86-64 c32rtomb declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <uchar.h>

using c32rtomb_signature = size_t (*)(char *, char32_t, mbstate_t *);

static_assert(sizeof(char32_t) == 4, "x86 char32_t is 32-bit");
static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t is eight bytes");
static_assert(__is_same(decltype(&c32rtomb), c32rtomb_signature),
              "C++ c32rtomb declaration");

static c32rtomb_signature c32rtomb_function __attribute__((used)) = c32rtomb;

int crabc_x86_64_c32rtomb_header_abi_probe_cpp()
{
    return c32rtomb_function != nullptr ? 0 : 1;
}
