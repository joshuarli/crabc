/* Source-only Linux/x86-64 <string.h> byte-string declaration probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>
#include <strings.h>

typedef char *(*char_search_signature)(const char *, int);
typedef int (*compare_signature)(const char *, const char *);
typedef int (*bounded_compare_signature)(const char *, const char *, size_t);
typedef size_t (*span_signature)(const char *, const char *);
typedef size_t (*length_signature)(const char *);
typedef size_t (*bounded_length_signature)(const char *, size_t);

static char_search_signature strchr_signature = strchr;
static char_search_signature strrchr_signature = strrchr;
static compare_signature strcmp_signature = strcmp;
static bounded_compare_signature strncmp_signature = strncmp;
static span_signature strcspn_signature = strcspn;
static span_signature strspn_signature = strspn;
static length_signature strlen_signature = strlen;
static bounded_length_signature strnlen_signature = strnlen;
static char *(*strpbrk_signature)(const char *, const char *) = strpbrk;
static char *(*strstr_signature)(const char *, const char *) = strstr;

#if defined(CRABC_EXPECT_GNU)
static char_search_signature strchrnul_signature = strchrnul;
#endif

#if defined(CRABC_EXPECT_ALIASES)
static char_search_signature index_signature = index;
static char_search_signature rindex_signature = rindex;
#endif

/* This opt-in reference is expected to fail under strict POSIX selectors. */
#if defined(CRABC_REQUIRE_STRCHRNUL)
static char_search_signature required_strchrnul_signature = strchrnul;
#endif

int crabc_x86_64_byte_strings_header_abi_probe(void)
{
    (void)strchr_signature;
    (void)strrchr_signature;
    (void)strcmp_signature;
    (void)strncmp_signature;
    (void)strcspn_signature;
    (void)strspn_signature;
    (void)strlen_signature;
    (void)strnlen_signature;
    (void)strpbrk_signature;
    (void)strstr_signature;
#if defined(CRABC_EXPECT_GNU)
    (void)strchrnul_signature;
#endif
#if defined(CRABC_EXPECT_ALIASES)
    (void)index_signature;
    (void)rindex_signature;
#endif
#if defined(CRABC_REQUIRE_STRCHRNUL)
    (void)required_strchrnul_signature;
#endif
    return 0;
}
