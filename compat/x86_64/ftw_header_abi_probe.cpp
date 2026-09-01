/* Linux/x86-64 <ftw.h> C++ declaration and C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FTW_EXPECT_FTW_VISIBLE) + \
    defined(CRABC_FTW_REQUIRE_FTW_HIDDEN)) != 1
#error "select exactly one ftw visibility class"
#endif

#include <ftw.h>

using ftw_callback_signature = int (*)(const char *, const struct stat *, int);
using nftw_callback_signature = int (*)(const char *, const struct stat *, int,
    struct FTW *);
using ftw_signature = int (*)(const char *, ftw_callback_signature, int);
using nftw_signature = int (*)(const char *, nftw_callback_signature, int, int);

static_assert(sizeof(struct FTW) == 8 && alignof(struct FTW) == 4 &&
    __builtin_offsetof(struct FTW, base) == 0 &&
    __builtin_offsetof(struct FTW, level) == 4, "x86 FTW record layout");
static_assert(FTW_F == 1 && FTW_D == 2 && FTW_DNR == 3 && FTW_NS == 4 &&
    FTW_SL == 5 && FTW_DP == 6 && FTW_SLN == 7 && FTW_PHYS == 1 &&
    FTW_MOUNT == 2 && FTW_CHDIR == 4 && FTW_DEPTH == 8, "FTW values");
static_assert(__is_same(decltype(&nftw), nftw_signature), "nftw declaration");

extern "C" int nftw(const char *, nftw_callback_signature, int, int);
__attribute__((used)) static nftw_signature crabc_nftw_reference = nftw;

#if defined(CRABC_FTW_EXPECT_FTW_VISIBLE)
static_assert(__is_same(decltype(&ftw), ftw_signature), "ftw declaration");
extern "C" int ftw(const char *, ftw_callback_signature, int);
__attribute__((used)) static ftw_signature crabc_ftw_reference = ftw;
#endif

#if defined(CRABC_FTW_REQUIRE_LARGEFILE_ALIASES)
#ifndef ftw64
#error "_LARGEFILE64_SOURCE must provide ftw64"
#endif
#ifndef nftw64
#error "_LARGEFILE64_SOURCE must provide nftw64"
#endif
static_assert(__is_same(decltype(&ftw64), ftw_signature),
    "ftw64 alias declaration");
static_assert(__is_same(decltype(&nftw64), nftw_signature),
    "nftw64 alias declaration");
__attribute__((used)) static ftw_signature crabc_ftw64_reference = ftw64;
__attribute__((used)) static nftw_signature crabc_nftw64_reference = nftw64;
#endif

#if defined(CRABC_FTW_REQUIRE_FTW_HIDDEN)
__attribute__((used)) static ftw_signature crabc_ftw_hidden = ftw;
#endif

extern "C" int crabc_x86_64_ftw_header_abi_probe_cpp()
{
    return 0;
}
