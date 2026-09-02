/* Pinned-musl/project Linux/x86-64 C11 stateful <uchar.h> declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <uchar.h>

typedef size_t (*c16rtomb_signature)(char *, char16_t, mbstate_t *);
typedef size_t (*mbrtoc16_signature)(char16_t *, const char *, size_t, mbstate_t *);
typedef size_t (*mbrtoc32_signature)(char32_t *, const char *, size_t, mbstate_t *);

_Static_assert(sizeof(char16_t) == 2, "x86 char16_t is 16-bit");
_Static_assert(sizeof(char32_t) == 4, "x86 char32_t is 32-bit");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t is eight bytes");
_Static_assert(
    __builtin_types_compatible_p(__typeof__(&c16rtomb), c16rtomb_signature),
    "c16rtomb declaration");
_Static_assert(
    __builtin_types_compatible_p(__typeof__(&mbrtoc16), mbrtoc16_signature),
    "mbrtoc16 declaration");
_Static_assert(
    __builtin_types_compatible_p(__typeof__(&mbrtoc32), mbrtoc32_signature),
    "mbrtoc32 declaration");

static c16rtomb_signature c16rtomb_function __attribute__((used)) = c16rtomb;
static mbrtoc16_signature mbrtoc16_function __attribute__((used)) = mbrtoc16;
static mbrtoc32_signature mbrtoc32_function __attribute__((used)) = mbrtoc32;

int crabc_x86_64_uchar_stateful_header_abi_probe(void)
{
    return c16rtomb_function != (c16rtomb_signature)0 &&
            mbrtoc16_function != (mbrtoc16_signature)0 &&
            mbrtoc32_function != (mbrtoc32_signature)0
        ? 0
        : 1;
}
