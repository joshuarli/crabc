/* Source-only Linux/x86-64 <inttypes.h> intmax arithmetic declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <inttypes.h>

_Static_assert(sizeof(intmax_t) == 8, "intmax_t width");
_Static_assert(__builtin_types_compatible_p(intmax_t, long),
    "intmax_t typedef");
_Static_assert(sizeof(imaxdiv_t) == 16 && offsetof(imaxdiv_t, quot) == 0 &&
    offsetof(imaxdiv_t, rem) == 8, "imaxdiv_t layout");
_Static_assert(_Alignof(imaxdiv_t) == 8, "imaxdiv_t alignment");

typedef intmax_t (*imaxabs_signature)(intmax_t);
typedef imaxdiv_t (*imaxdiv_signature)(intmax_t, intmax_t);

static imaxabs_signature imaxabs_function = imaxabs;
static imaxdiv_signature imaxdiv_function = imaxdiv;

int crabc_x86_64_intmax_arithmetic_header_abi_probe(void)
{
    imaxdiv_t quotient = imaxdiv_function(7, 3);

    return imaxabs_function(-1) == 1 && quotient.quot == 2 && quotient.rem == 1
        ? 0 : 1;
}
