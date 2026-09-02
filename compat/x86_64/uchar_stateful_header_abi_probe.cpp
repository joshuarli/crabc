/* C++17 companion for the Linux/x86-64 stateful <uchar.h> declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <uchar.h>

using c16rtomb_signature = size_t (*)(char *, char16_t, mbstate_t *);
using mbrtoc16_signature = size_t (*)(char16_t *, const char *, size_t, mbstate_t *);
using mbrtoc32_signature = size_t (*)(char32_t *, const char *, size_t, mbstate_t *);

static_assert(sizeof(char16_t) == 2, "x86 char16_t is 16-bit");
static_assert(sizeof(char32_t) == 4, "x86 char32_t is 32-bit");
static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t is eight bytes");
static_assert(__is_same(decltype(&c16rtomb), c16rtomb_signature),
              "C++ c16rtomb declaration");
static_assert(__is_same(decltype(&mbrtoc16), mbrtoc16_signature),
              "C++ mbrtoc16 declaration");
static_assert(__is_same(decltype(&mbrtoc32), mbrtoc32_signature),
              "C++ mbrtoc32 declaration");

static c16rtomb_signature c16rtomb_function __attribute__((used)) = c16rtomb;
static mbrtoc16_signature mbrtoc16_function __attribute__((used)) = mbrtoc16;
static mbrtoc32_signature mbrtoc32_function __attribute__((used)) = mbrtoc32;

int crabc_x86_64_uchar_stateful_header_abi_probe_cpp()
{
    return c16rtomb_function != nullptr && mbrtoc16_function != nullptr &&
            mbrtoc32_function != nullptr
        ? 0
        : 1;
}
