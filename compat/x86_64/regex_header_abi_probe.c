/* Native Linux/x86-64 <regex.h> declaration and record ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <regex.h>
#include <stddef.h>

typedef int (*regcomp_signature)(regex_t *restrict, const char *restrict, int);
typedef int (*regexec_signature)(const regex_t *restrict, const char *restrict,
    size_t, regmatch_t *restrict, int);
typedef size_t (*regerror_signature)(int, const regex_t *restrict,
    char *restrict, size_t);
typedef void (*regfree_signature)(regex_t *);

_Static_assert(sizeof(regex_t) == 64 && _Alignof(regex_t) == 8,
    "x86 regex_t size/alignment");
_Static_assert(offsetof(regex_t, re_nsub) == 0 &&
    offsetof(regex_t, __opaque) == 8 &&
    offsetof(regex_t, __padding) == 16 &&
    offsetof(regex_t, __nsub2) == 48 &&
    offsetof(regex_t, __padding2) == 56,
    "x86 regex_t field offsets");
_Static_assert(sizeof(regoff_t) == 8 && _Alignof(regoff_t) == 8,
    "x86 regoff_t width/alignment");
_Static_assert(sizeof(regmatch_t) == 16 && _Alignof(regmatch_t) == 8 &&
    offsetof(regmatch_t, rm_so) == 0 && offsetof(regmatch_t, rm_eo) == 8,
    "x86 regmatch_t layout");

_Static_assert(REG_EXTENDED == 1 && REG_ICASE == 2 && REG_NEWLINE == 4 &&
    REG_NOSUB == 8 && REG_NOTBOL == 1 && REG_NOTEOL == 2,
    "POSIX regex flag values");
_Static_assert(REG_NOMATCH == 1 && REG_BADPAT == 2 && REG_ECOLLATE == 3 &&
    REG_ECTYPE == 4 && REG_EESCAPE == 5 && REG_ESUBREG == 6 &&
    REG_EBRACK == 7 && REG_EPAREN == 8 && REG_EBRACE == 9 &&
    REG_BADBR == 10 && REG_ERANGE == 11 && REG_ESPACE == 12 &&
    REG_BADRPT == 13 && REG_ENOSYS == -1,
    "POSIX regex result values");

_Static_assert(__builtin_types_compatible_p(__typeof__(&regcomp),
    regcomp_signature), "regcomp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regexec),
    regexec_signature), "regexec declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regerror),
    regerror_signature), "regerror declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regfree),
    regfree_signature), "regfree declaration");

int crabc_x86_64_regex_header_abi_probe(void)
{
    return 0;
}
