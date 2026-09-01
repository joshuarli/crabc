/* Pinned-musl/project Linux/x86-64 GNU/BSD issetugid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*issetugid_signature)(void);

#if defined(CRABC_EXPECT_ISSETUGID)
_Static_assert(__builtin_types_compatible_p(__typeof__(&issetugid),
    issetugid_signature), "issetugid declaration");
static issetugid_signature issetugid_function __attribute__((used)) = issetugid;
#endif

#if defined(CRABC_REQUIRE_ISSETUGID_HIDDEN)
static issetugid_signature issetugid_must_be_hidden __attribute__((used)) = issetugid;
#endif

int crabc_x86_64_issetugid_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_ISSETUGID)
    return issetugid_function != (issetugid_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
