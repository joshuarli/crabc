/* Source-only Linux/x86-64 GNU <stdio.h> renameat2 declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdio.h>

typedef int (*renameat2_signature)(int, const char *, int, const char *,
                                   unsigned);

#if defined(CRABC_EXPECT_RENAMEAT2)
_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 renameat2 int ABI");
_Static_assert(sizeof(unsigned) == 4 && _Alignof(unsigned) == 4,
               "x86 renameat2 unsigned ABI");
_Static_assert(sizeof(char *) == 8 && _Alignof(char *) == 8,
               "x86 renameat2 pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&renameat2),
                                             renameat2_signature),
               "renameat2 declaration");
static renameat2_signature renameat2_function __attribute__((used)) = renameat2;
#endif

#if defined(CRABC_EXPECT_RENAMEAT2_GNU_FLAGS)
_Static_assert(RENAME_NOREPLACE == 1 && RENAME_EXCHANGE == 2 &&
                   RENAME_WHITEOUT == 4,
               "x86 renameat2 GNU flag constants");
#endif

#if defined(CRABC_REQUIRE_RENAMEAT2_HIDDEN)
#ifdef RENAME_NOREPLACE
#error "renameat2 GNU flags must be hidden in this C profile"
#endif
static renameat2_signature renameat2_must_be_hidden __attribute__((used)) =
    renameat2;
#endif

int crabc_x86_64_renameat2_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_RENAMEAT2)
    return renameat2_function != (renameat2_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
