/* C++17 companion for the Linux/x86-64 GNU <stdio.h> renameat2 declaration. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdio.h>

using renameat2_signature = int (*)(int, const char *, int, const char *,
                                    unsigned);

#if defined(CRABC_EXPECT_RENAMEAT2)
static_assert(sizeof(int) == 4 && alignof(int) == 4,
              "C++ x86 renameat2 int ABI");
static_assert(sizeof(unsigned) == 4 && alignof(unsigned) == 4,
              "C++ x86 renameat2 unsigned ABI");
static_assert(sizeof(char *) == 8 && alignof(char *) == 8,
              "C++ x86 renameat2 pointer ABI");
static_assert(__is_same(decltype(&renameat2), renameat2_signature),
              "C++ renameat2 declaration");
__attribute__((used)) static renameat2_signature renameat2_function = renameat2;
#endif

#if defined(CRABC_EXPECT_RENAMEAT2_GNU_FLAGS)
static_assert(RENAME_NOREPLACE == 1 && RENAME_EXCHANGE == 2 &&
                  RENAME_WHITEOUT == 4,
              "C++ x86 renameat2 GNU flag constants");
#endif

#if defined(CRABC_REQUIRE_RENAMEAT2_HIDDEN)
#ifdef RENAME_NOREPLACE
#error "renameat2 GNU flags must be hidden in this C++ profile"
#endif
__attribute__((used)) static renameat2_signature renameat2_must_be_hidden =
    renameat2;
#endif

int crabc_x86_64_renameat2_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_RENAMEAT2)
    return renameat2_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
