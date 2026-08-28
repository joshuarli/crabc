/* C++ companion for the Linux/x86-64 <strings.h> find-first-set probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <strings.h>

#if defined(CRABC_EXPECT_FFS)
using ffs_signature = int (*)(int);
using ffsl_signature = int (*)(long);
using ffsll_signature = int (*)(long long);

static_assert(__is_same(decltype(&ffs), ffs_signature), "ffs declaration");
static_assert(__is_same(decltype(&ffsl), ffsl_signature), "ffsl declaration");
static_assert(__is_same(decltype(&ffsll), ffsll_signature), "ffsll declaration");

static ffs_signature ffs_function = ffs;
static ffsl_signature ffsl_function = ffsl;
static ffsll_signature ffsll_function = ffsll;
#endif

/* An opt-in reference that must fail under strict/POSIX-only selectors. */
#if defined(CRABC_REQUIRE_FFS_HIDDEN)
using hidden_ffs_signature = int (*)(int);
static hidden_ffs_signature ffs_must_be_hidden = ffs;
#endif

int crabc_x86_64_ffs_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_FFS)
    return ffs_function(1) + ffsl_function(1L) + ffsll_function(1LL) == 3
        ? 0 : 1;
#else
    return 0;
#endif
}
