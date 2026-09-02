/* Pinned-musl/project Linux/x86-64 stateful byte-string declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>
#include <string.h>

typedef char *(*dirname_signature)(char *);
typedef char *(*strcasestr_signature)(const char *, const char *);
typedef char *(*strtok_r_signature)(char *restrict, const char *restrict,
    char **restrict);

#if defined(CRABC_EXPECT_DIRNAME)
_Static_assert(__builtin_types_compatible_p(__typeof__(&dirname), dirname_signature),
    "dirname declaration");
static dirname_signature dirname_function __attribute__((used)) = dirname;
#endif

#if defined(CRABC_EXPECT_STRCASESTR)
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcasestr), strcasestr_signature),
    "strcasestr declaration");
static strcasestr_signature strcasestr_function __attribute__((used)) = strcasestr;
#endif

#if defined(CRABC_EXPECT_STRTOK_R)
_Static_assert(__builtin_types_compatible_p(__typeof__(&strtok_r), strtok_r_signature),
    "strtok_r declaration");
static strtok_r_signature strtok_r_function __attribute__((used)) = strtok_r;
#endif

#if defined(CRABC_REQUIRE_STRCASESTR_HIDDEN)
static strcasestr_signature required_strcasestr_hidden = strcasestr;
#endif

#if defined(CRABC_REQUIRE_STRTOK_R_HIDDEN)
static strtok_r_signature required_strtok_r_hidden = strtok_r;
#endif

int crabc_x86_64_stateful_byte_strings_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_DIRNAME)
    (void)dirname_function;
#endif
#if defined(CRABC_EXPECT_STRCASESTR)
    (void)strcasestr_function;
#endif
#if defined(CRABC_EXPECT_STRTOK_R)
    (void)strtok_r_function;
#endif
    return 0;
}
