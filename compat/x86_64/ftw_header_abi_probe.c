/* Linux/x86-64 <ftw.h> declaration and feature-visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FTW_EXPECT_FTW_VISIBLE) + \
    defined(CRABC_FTW_REQUIRE_FTW_HIDDEN)) != 1
#error "select exactly one ftw visibility class"
#endif

#include <stddef.h>
#include <ftw.h>

typedef int (*ftw_callback_signature)(const char *, const struct stat *, int);
typedef int (*nftw_callback_signature)(const char *, const struct stat *, int,
    struct FTW *);
typedef int (*ftw_signature)(const char *, ftw_callback_signature, int);
typedef int (*nftw_signature)(const char *, nftw_callback_signature, int, int);

_Static_assert(sizeof(struct FTW) == 8 && _Alignof(struct FTW) == 4 &&
    offsetof(struct FTW, base) == 0 && offsetof(struct FTW, level) == 4,
    "x86 FTW record layout");
_Static_assert(FTW_F == 1 && FTW_D == 2 && FTW_DNR == 3 && FTW_NS == 4 &&
    FTW_SL == 5 && FTW_DP == 6 && FTW_SLN == 7 && FTW_PHYS == 1 &&
    FTW_MOUNT == 2 && FTW_CHDIR == 4 && FTW_DEPTH == 8,
    "FTW values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nftw), nftw_signature),
    "nftw declaration");

__attribute__((used)) static nftw_signature crabc_nftw_reference = nftw;

#if defined(CRABC_FTW_EXPECT_FTW_VISIBLE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&ftw), ftw_signature),
    "ftw declaration");
__attribute__((used)) static ftw_signature crabc_ftw_reference = ftw;
#endif

#if defined(CRABC_FTW_REQUIRE_LARGEFILE_ALIASES)
#ifndef ftw64
#error "_LARGEFILE64_SOURCE must provide ftw64"
#endif
#ifndef nftw64
#error "_LARGEFILE64_SOURCE must provide nftw64"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&ftw64), ftw_signature),
    "ftw64 alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nftw64), nftw_signature),
    "nftw64 alias declaration");
__attribute__((used)) static ftw_signature crabc_ftw64_reference = ftw64;
__attribute__((used)) static nftw_signature crabc_nftw64_reference = nftw64;
#endif

#if defined(CRABC_FTW_REQUIRE_FTW_HIDDEN)
__attribute__((used)) static ftw_signature crabc_ftw_hidden = ftw;
#endif

int crabc_x86_64_ftw_header_abi_probe(void)
{
    return 0;
}
