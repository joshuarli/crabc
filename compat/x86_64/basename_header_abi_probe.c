/* Pinned-musl/project Linux/x86-64 basename declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>

typedef char *(*basename_signature)(char *);

#if defined(CRABC_EXPECT_BASENAME)
_Static_assert(__builtin_types_compatible_p(__typeof__(&basename), basename_signature),
    "basename declaration");
static basename_signature basename_function __attribute__((used)) = basename;
#endif

int crabc_x86_64_basename_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_BASENAME)
    return basename_function != (basename_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
