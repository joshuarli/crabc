/* C++ companion for the Linux/x86-64 <inttypes.h> intmax arithmetic probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <inttypes.h>

static_assert(sizeof(intmax_t) == 8, "intmax_t width");
static_assert(__is_same(intmax_t, long), "intmax_t typedef");
static_assert(sizeof(imaxdiv_t) == 16 && offsetof(imaxdiv_t, quot) == 0 &&
    offsetof(imaxdiv_t, rem) == 8, "imaxdiv_t layout");
static_assert(alignof(imaxdiv_t) == 8, "imaxdiv_t alignment");

using imaxabs_signature = intmax_t (*)(intmax_t);
using imaxdiv_signature = imaxdiv_t (*)(intmax_t, intmax_t);

static_assert(__is_same(decltype(&imaxabs), imaxabs_signature),
    "imaxabs declaration");
static_assert(__is_same(decltype(&imaxdiv), imaxdiv_signature),
    "imaxdiv declaration");

static imaxabs_signature imaxabs_function = imaxabs;
static imaxdiv_signature imaxdiv_function = imaxdiv;

int crabc_x86_64_intmax_arithmetic_header_abi_probe_cpp()
{
    imaxdiv_t quotient = imaxdiv_function(7, 3);

    return imaxabs_function(-1) == 1 && quotient.quot == 2 && quotient.rem == 1
        ? 0 : 1;
}
