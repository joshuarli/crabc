/* Source-only Linux/x86-64 <ctype.h> declaration and feature-gate probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <ctype.h>

typedef int (*ctype_signature)(int);

static ctype_signature isalnum_signature = &isalnum;
static ctype_signature isalpha_signature = &isalpha;
static ctype_signature isblank_signature = &isblank;
static ctype_signature iscntrl_signature = &iscntrl;
static ctype_signature isdigit_signature = &isdigit;
static ctype_signature isgraph_signature = &isgraph;
static ctype_signature islower_signature = &islower;
static ctype_signature isprint_signature = &isprint;
static ctype_signature ispunct_signature = &ispunct;
static ctype_signature isspace_signature = &isspace;
static ctype_signature isupper_signature = &isupper;
static ctype_signature isxdigit_signature = &isxdigit;
static ctype_signature tolower_signature = &tolower;
static ctype_signature toupper_signature = &toupper;

#if defined(CRABC_EXPECT_C_FAST_CTYPE)
static ctype_signature __isspace_signature = &__isspace;
#ifndef isalpha
#error "C ctype fast path must expose isalpha"
#endif
#ifndef isdigit
#error "C ctype fast path must expose isdigit"
#endif
#ifndef islower
#error "C ctype fast path must expose islower"
#endif
#ifndef isupper
#error "C ctype fast path must expose isupper"
#endif
#ifndef isprint
#error "C ctype fast path must expose isprint"
#endif
#ifndef isgraph
#error "C ctype fast path must expose isgraph"
#endif
#ifndef isspace
#error "C ctype fast path must expose isspace"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&__isspace),
    ctype_signature), "__isspace inline declaration");

/* Type-check exact C-only macros without selecting their external fallbacks. */
static int ctype_fast_path_expression_formation(void)
{
    return !isalpha('A') || !isalpha('z') || isalpha('0') ||
        !isdigit('0') || !isdigit('9') || isdigit('a') ||
        !islower('a') || islower('A') || !isupper('A') || isupper('a') ||
        !isprint(' ') || isprint(0x7f) || !isgraph('!') || isgraph(' ') ||
        !isspace(' ') || !isspace('\t') || isspace('A');
}
#endif

#if defined(CRABC_EXPECT_EXTENDED_CTYPE)
static ctype_signature isascii_signature = &isascii;
static ctype_signature toascii_signature = &toascii;
#ifndef isascii
#error "isascii must be a C-only macro in the selected ctype profile"
#endif
#ifndef _tolower
#error "_tolower must be visible in the selected ctype profile"
#endif
#ifndef _toupper
#error "_toupper must be visible in the selected ctype profile"
#endif
_Static_assert(isascii(0), "isascii accepts zero");
_Static_assert(isascii(127), "isascii accepts the seven-bit maximum");
_Static_assert(!isascii(128), "isascii rejects bit eight");
_Static_assert(!isascii(-1), "isascii rejects negative input");
_Static_assert(
    _Generic(isascii(0), int: 1, default: 0), "isascii has int result"
);
_Static_assert(_tolower('A') == 'a', "_tolower ASCII case bit");
_Static_assert(_toupper('a') == 'A', "_toupper ASCII case bit");
_Static_assert(_tolower(0x80) == 0xa0, "_tolower has musl bitwise behavior");
_Static_assert(_toupper(0x80) == 0, "_toupper has musl bitwise behavior");
_Static_assert(_tolower(-1) == -1, "_tolower does not validate EOF");
_Static_assert(_toupper(-1) == 0x5f, "_toupper does not validate EOF");
_Static_assert(
    _Generic(_tolower('A'), int: 1, default: 0), "_tolower has int result"
);
_Static_assert(
    _Generic(_toupper('a'), int: 1, default: 0), "_toupper has int result"
);
#endif

/* Strict C succeeds only when the legacy case macros are absent. */
#if defined(CRABC_ASSERT_LEGACY_CASE_MACROS_HIDDEN)
#if defined(isascii) || defined(_tolower) || defined(_toupper)
#error "strict C must hide isascii, _tolower, and _toupper"
#endif
#endif

/* This branch compiles only as the strict-C feature-gate negative check. */
#if defined(CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN)
static ctype_signature required_isascii_signature = &isascii;
static ctype_signature required_toascii_signature = &toascii;
static int required_tolower = _tolower('A');
static int required_toupper = _toupper('a');
#endif

/* Musl intentionally exposes the fast-path implementation only to C. */
#if defined(CRABC_REQUIRE_C_FAST_CTYPE_HIDDEN)
#ifdef __isspace
#error "C++ must hide __isspace"
#endif
#if defined(isalpha) || defined(isdigit) || defined(islower) || \
    defined(isupper) || defined(isprint) || defined(isgraph) || defined(isspace)
#error "C++ must hide C-only ctype fast-path names"
#endif
#endif

int crabc_x86_64_ctype_header_abi_probe(void)
{
    (void)isalnum_signature;
    (void)isalpha_signature;
    (void)isblank_signature;
    (void)iscntrl_signature;
    (void)isdigit_signature;
    (void)isgraph_signature;
    (void)islower_signature;
    (void)isprint_signature;
    (void)ispunct_signature;
    (void)isspace_signature;
    (void)isupper_signature;
    (void)isxdigit_signature;
    (void)tolower_signature;
    (void)toupper_signature;
#if defined(CRABC_EXPECT_EXTENDED_CTYPE)
    (void)isascii_signature;
    (void)toascii_signature;
#endif
#if defined(CRABC_EXPECT_C_FAST_CTYPE)
    (void)__isspace_signature;
    (void)ctype_fast_path_expression_formation;
#endif
#if defined(CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN)
    (void)required_isascii_signature;
    (void)required_toascii_signature;
    (void)required_tolower;
    (void)required_toupper;
#endif
    return 0;
}
