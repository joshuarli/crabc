/* Source-only Linux/x86-64 integer-parsing declaration ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <inttypes.h>
#include <stdlib.h>

typedef int (*atoi_signature)(const char *);
typedef long (*atol_signature)(const char *);
typedef long long (*atoll_signature)(const char *);
typedef long (*strtol_signature)(const char *, char **, int);
typedef unsigned long (*strtoul_signature)(const char *, char **, int);
typedef long long (*strtoll_signature)(const char *, char **, int);
typedef unsigned long long (*strtoull_signature)(const char *, char **, int);
typedef intmax_t (*strtoimax_signature)(const char *, char **, int);
typedef uintmax_t (*strtoumax_signature)(const char *, char **, int);

static atoi_signature atoi_function = atoi;
static atol_signature atol_function = atol;
static atoll_signature atoll_function = atoll;
static strtol_signature strtol_function = strtol;
static strtoul_signature strtoul_function = strtoul;
static strtoll_signature strtoll_function = strtoll;
static strtoull_signature strtoull_function = strtoull;
static strtoimax_signature strtoimax_function = strtoimax;
static strtoumax_signature strtoumax_function = strtoumax;

_Static_assert(sizeof(intmax_t) == sizeof(long), "x86 LP64 intmax_t width");
_Static_assert(sizeof(uintmax_t) == sizeof(unsigned long), "x86 LP64 uintmax_t width");

int crabc_x86_64_integer_parse_header_abi_probe(void)
{
    (void)atoi_function;
    (void)atol_function;
    (void)atoll_function;
    (void)strtol_function;
    (void)strtoul_function;
    (void)strtoll_function;
    (void)strtoull_function;
    (void)strtoimax_function;
    (void)strtoumax_function;
    return 0;
}
