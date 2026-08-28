/* Source-only Linux/x86-64 <string.h> C-string copy declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

typedef char *(*copy_signature)(char *, const char *);
typedef char *(*bounded_copy_signature)(char *, const char *, size_t);
typedef size_t (*sized_copy_signature)(char *, const char *, size_t);

static copy_signature strcpy_signature = strcpy;
static bounded_copy_signature strncpy_signature = strncpy;
static copy_signature strcat_signature = strcat;
static bounded_copy_signature strncat_signature = strncat;

#if defined(CRABC_EXPECT_POSIX_COPY)
static copy_signature stpcpy_signature = stpcpy;
static bounded_copy_signature stpncpy_signature = stpncpy;
#endif

#if defined(CRABC_EXPECT_GNU_COPY)
static sized_copy_signature strlcpy_signature = strlcpy;
static sized_copy_signature strlcat_signature = strlcat;
#endif

/* These branches compile only as feature-gate negative checks. */
#if defined(CRABC_REQUIRE_POSIX_COPY_HIDDEN)
static copy_signature required_stpcpy_signature = stpcpy;
#endif

#if defined(CRABC_REQUIRE_GNU_COPY_HIDDEN)
static sized_copy_signature required_strlcpy_signature = strlcpy;
#endif

int crabc_x86_64_string_copy_header_abi_probe(void)
{
    (void)strcpy_signature;
    (void)strncpy_signature;
    (void)strcat_signature;
    (void)strncat_signature;
#if defined(CRABC_EXPECT_POSIX_COPY)
    (void)stpcpy_signature;
    (void)stpncpy_signature;
#endif
#if defined(CRABC_EXPECT_GNU_COPY)
    (void)strlcpy_signature;
    (void)strlcat_signature;
#endif
#if defined(CRABC_REQUIRE_POSIX_COPY_HIDDEN)
    (void)required_stpcpy_signature;
#endif
#if defined(CRABC_REQUIRE_GNU_COPY_HIDDEN)
    (void)required_strlcpy_signature;
#endif
    return 0;
}
