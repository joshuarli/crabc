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

#if defined(CRABC_EXPECT_EXTENDED_CTYPE)
static ctype_signature isascii_signature = &isascii;
static ctype_signature toascii_signature = &toascii;
#endif

/* This branch compiles only as the strict-C feature-gate negative check. */
#if defined(CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN)
static ctype_signature required_isascii_signature = &isascii;
static ctype_signature required_toascii_signature = &toascii;
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
#if defined(CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN)
    (void)required_isascii_signature;
    (void)required_toascii_signature;
#endif
    return 0;
}
