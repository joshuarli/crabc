/* Linux/x86-64 <stdio.h> temporary-name declaration profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdio.h>

typedef char *(*tmpnam_signature)(char *);
typedef char *(*tempnam_signature)(const char *, const char *);

/* tmpnam and its caller-buffer bound are ISO C surface in every profile. */
_Static_assert(L_tmpnam == 20, "L_tmpnam value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tmpnam),
    tmpnam_signature), "tmpnam declaration");
static tmpnam_signature tmpnam_function = tmpnam;

/* tempnam and P_tmpdir are the separately selected legacy extension pair. */
#if defined(CRABC_EXPECT_TEMPNAM)
_Static_assert(__builtin_types_compatible_p(__typeof__(&tempnam),
    tempnam_signature), "tempnam declaration");
_Static_assert(sizeof(P_tmpdir) == sizeof("/tmp"), "P_tmpdir extent");
static tempnam_signature tempnam_function = tempnam;
static const char *const p_tmpdir_value = P_tmpdir;
#endif

/* This branch is deliberately compiled only for C negative-profile checks. */
#if defined(CRABC_REQUIRE_TEMPNAM_HIDDEN)
static tempnam_signature tempnam_must_be_hidden = tempnam;
static const char *const p_tmpdir_must_be_hidden = P_tmpdir;
#endif

int crabc_x86_64_temporary_names_header_abi_probe(void)
{
    (void)tmpnam_function;
#if defined(CRABC_EXPECT_TEMPNAM)
    (void)tempnam_function;
    (void)p_tmpdir_value;
#endif
#if defined(CRABC_REQUIRE_TEMPNAM_HIDDEN)
    (void)tempnam_must_be_hidden;
    (void)p_tmpdir_must_be_hidden;
#endif
    return 0;
}
