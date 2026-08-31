/* Source-only Linux/x86-64 <string.h> C-string-duplication declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

typedef char *(*duplicate_signature)(const char *);
typedef char *(*bounded_duplicate_signature)(const char *, size_t);

#if defined(CRABC_EXPECT_STRING_DUPLICATION)
static duplicate_signature strdup_signature = strdup;
static bounded_duplicate_signature strndup_signature = strndup;
#endif

/* This branch compiles only as a strict-selector negative check. */
#if defined(CRABC_REQUIRE_STRING_DUPLICATION_HIDDEN)
static duplicate_signature required_strdup_signature = strdup;
#endif

int crabc_x86_64_string_duplication_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_STRING_DUPLICATION)
    (void)strdup_signature;
    (void)strndup_signature;
#endif
#if defined(CRABC_REQUIRE_STRING_DUPLICATION_HIDDEN)
    (void)required_strdup_signature;
#endif
    return 0;
}
