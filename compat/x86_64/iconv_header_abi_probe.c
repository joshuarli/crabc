/* Linux/x86-64 C11 <iconv.h> selected UTF/ASCII ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <iconv.h>
#include <stddef.h>

_Static_assert(sizeof(iconv_t) == sizeof(void *), "iconv_t pointer ABI");
_Static_assert(_Alignof(iconv_t) == _Alignof(void *), "iconv_t alignment");

typedef iconv_t (*iconv_open_signature)(const char *, const char *);
typedef size_t (*iconv_signature)(iconv_t, char **__restrict,
    size_t *__restrict, char **__restrict, size_t *__restrict);
typedef int (*iconv_close_signature)(iconv_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&iconv_open),
    iconv_open_signature), "iconv_open declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&iconv),
    iconv_signature), "iconv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&iconv_close),
    iconv_close_signature), "iconv_close declaration");

static iconv_open_signature iconv_open_function = iconv_open;
static iconv_signature iconv_function = iconv;
static iconv_close_signature iconv_close_function = iconv_close;

int crabc_x86_64_iconv_header_abi_probe(void)
{
    return iconv_open_function != 0 && iconv_function != 0 &&
        iconv_close_function != 0 ? 0 : 1;
}
