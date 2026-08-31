/* Linux/x86-64 C++17 <iconv.h> selected UTF/ASCII ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <iconv.h>

static_assert(sizeof(iconv_t) == sizeof(void *), "iconv_t pointer ABI");
static_assert(alignof(iconv_t) == alignof(void *), "iconv_t alignment");

using iconv_open_signature = iconv_t (*)(const char *, const char *);
using iconv_signature = size_t (*)(iconv_t, char **, size_t *, char **,
    size_t *);
using iconv_close_signature = int (*)(iconv_t);

static_assert(__is_same(decltype(&iconv_open), iconv_open_signature),
    "iconv_open declaration");
static_assert(__is_same(decltype(&iconv), iconv_signature),
    "iconv declaration");
static_assert(__is_same(decltype(&iconv_close), iconv_close_signature),
    "iconv_close declaration");

static iconv_open_signature iconv_open_function = iconv_open;
static iconv_signature iconv_function = iconv;
static iconv_close_signature iconv_close_function = iconv_close;

int crabc_x86_64_iconv_header_abi_probe_cpp()
{
    return iconv_open_function != nullptr && iconv_function != nullptr &&
        iconv_close_function != nullptr ? 0 : 1;
}
