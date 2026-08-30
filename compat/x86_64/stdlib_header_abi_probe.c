/*
 * Linux/x86-64 <stdlib.h> feature-profile declaration probe.
 *
 * `run_stdlib_header_abi.sh` compiles this source against pinned musl 1.2.6
 * and against the project header tree under one explicitly named feature
 * profile.  The ordinary pass names only declarations that the profile must
 * expose.  The runner's separate hidden-witness pass deliberately names a
 * declaration that this profile must hide; that pass must fail to compile.
 *
 * This is a header-only contract probe.  It neither links nor selects a
 * crabc-libc artifact, runtime implementation, CRT, loader, or public x86
 * support claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_STDLIB_STRICT) + \
    defined(CRABC_STDLIB_POSIX_2008) + \
    defined(CRABC_STDLIB_XOPEN_700) + \
    defined(CRABC_STDLIB_GNU) + \
    defined(CRABC_STDLIB_BSD) + \
    defined(CRABC_STDLIB_LFS)) != 1
#error "select exactly one <stdlib.h> feature profile"
#endif

#include <stdlib.h>

#if !defined(CRABC_STDLIB_HIDDEN_WITNESS_ONLY)
#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)

typedef void *(*crabc_malloc_signature)(size_t);
typedef long (*crabc_strtol_signature)(const char *restrict, char **restrict,
    int);
typedef void (*crabc_qsort_signature)(void *, size_t, size_t,
    int (*)(const void *, const void *));

_Static_assert(CRABC_TYPE_IS(__typeof__(&malloc), crabc_malloc_signature),
    "malloc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtol), crabc_strtol_signature),
    "strtol declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&qsort), crabc_qsort_signature),
    "qsort declaration");
_Static_assert(sizeof(div_t) == 2 * sizeof(int) &&
    _Alignof(div_t) == _Alignof(int), "LP64 div_t ABI");
_Static_assert(sizeof(ldiv_t) == 2 * sizeof(long) &&
    _Alignof(ldiv_t) == _Alignof(long), "LP64 ldiv_t ABI");
_Static_assert(sizeof(lldiv_t) == 2 * sizeof(long long) &&
    _Alignof(lldiv_t) == _Alignof(long long), "LP64 lldiv_t ABI");

#if defined(CRABC_STDLIB_STRICT)
#if defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || \
    defined(_BSD_SOURCE) || defined(_LARGEFILE64_SOURCE)
#error "strict C11 must not select a POSIX, X/Open, GNU, BSD, or LFS profile"
#endif
#endif

#if defined(CRABC_STDLIB_POSIX_2008)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L
#error "POSIX.1-2008 profile must retain _POSIX_C_SOURCE=200809L"
#endif
#endif

#if defined(CRABC_STDLIB_XOPEN_700)
#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE != 700
#error "X/Open Issue 7 profile must retain _XOPEN_SOURCE=700"
#endif
#endif

#if defined(CRABC_STDLIB_GNU)
#ifndef _GNU_SOURCE
#error "GNU profile must retain _GNU_SOURCE"
#endif
#endif

#if defined(CRABC_STDLIB_BSD)
#ifndef _BSD_SOURCE
#error "BSD profile must retain _BSD_SOURCE"
#endif
#endif

#if defined(CRABC_STDLIB_LFS)
#ifndef _LARGEFILE64_SOURCE
#error "LFS profile must retain _LARGEFILE64_SOURCE"
#endif
#ifndef mkstemp64
#error "musl LFS profile must expose the mkstemp64 macro alias"
#endif
#ifndef mkostemp64
#error "musl LFS profile must expose the mkostemp64 macro alias"
#endif
#endif

#if defined(CRABC_STDLIB_POSIX_2008) || \
    defined(CRABC_STDLIB_XOPEN_700) || \
    defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
#if !defined(WNOHANG) || !defined(WUNTRACED) || !defined(WEXITSTATUS) || \
    !defined(WTERMSIG) || !defined(WSTOPSIG) || !defined(WIFEXITED) || \
    !defined(WIFSIGNALED) || !defined(WIFSTOPPED)
#error "POSIX/XOPEN/GNU/BSD profiles must expose musl wait-status macros"
#endif
_Static_assert(WNOHANG == 1 && WUNTRACED == 2,
    "musl wait option values");
_Static_assert(WEXITSTATUS(0x1234) == 0x12 && WTERMSIG(0x127f) == 0x7f &&
    WSTOPSIG(0x137f) == 0x13, "musl wait-status extraction");
_Static_assert(WIFEXITED(0x1200) && !WIFEXITED(0x127f),
    "musl WIFEXITED status partition");
_Static_assert(!WIFSTOPPED(0x007f),
    "musl WIFSTOPPED rejects a stop status with no stopping signal");
_Static_assert(WIFSTOPPED(0x137f),
    "musl WIFSTOPPED accepts a stopped child status");
_Static_assert(WIFSIGNALED(0x0009) && WIFSIGNALED(0x007f) &&
    !WIFSIGNALED(0x137f),
    "musl WIFSIGNALED status partition");
#else
#if defined(WNOHANG) || defined(WUNTRACED) || defined(WEXITSTATUS) || \
    defined(WTERMSIG) || defined(WSTOPSIG) || defined(WIFEXITED) || \
    defined(WIFSIGNALED) || defined(WIFSTOPPED)
#error "strict and LFS-only profiles must hide musl wait-status macros"
#endif
#endif

#if defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
#ifndef WIFCONTINUED
#error "musl GNU/BSD profiles expose WIFCONTINUED"
#endif
_Static_assert(WIFCONTINUED(0xffff), "musl WIFCONTINUED true status");
_Static_assert(WCOREDUMP(0x80), "musl WCOREDUMP core-bit status");
#else
#if defined(WIFCONTINUED) || defined(WCOREDUMP)
#error "non-GNU/BSD profiles must hide musl WIFCONTINUED and WCOREDUMP"
#endif
#endif

#if defined(CRABC_STDLIB_POSIX_2008) || \
    defined(CRABC_STDLIB_XOPEN_700) || \
    defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
typedef int (*crabc_posix_memalign_signature)(void **, size_t, size_t);
typedef int (*crabc_setenv_signature)(const char *, const char *, int);
typedef int (*crabc_unsetenv_signature)(const char *);
typedef int (*crabc_mkstemp_signature)(char *);
typedef int (*crabc_mkostemp_signature)(char *, int);
typedef char *(*crabc_mkdtemp_signature)(char *);
typedef int (*crabc_getsubopt_signature)(char **, char *const *, char **);
typedef int (*crabc_rand_r_signature)(unsigned *);

_Static_assert(CRABC_TYPE_IS(__typeof__(&posix_memalign),
    crabc_posix_memalign_signature), "posix_memalign declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&setenv), crabc_setenv_signature),
    "setenv declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&unsetenv), crabc_unsetenv_signature),
    "unsetenv declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mkstemp), crabc_mkstemp_signature),
    "mkstemp declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mkostemp), crabc_mkostemp_signature),
    "mkostemp declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mkdtemp), crabc_mkdtemp_signature),
    "mkdtemp declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&getsubopt),
    crabc_getsubopt_signature), "getsubopt declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&rand_r), crabc_rand_r_signature),
    "rand_r declaration");
#endif

#if defined(CRABC_STDLIB_XOPEN_700) || \
    defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
typedef char *(*crabc_realpath_signature)(const char *restrict,
    char *restrict);
typedef int (*crabc_putenv_signature)(char *);
typedef double (*crabc_drand48_signature)(void);
typedef int (*crabc_posix_openpt_signature)(int);

_Static_assert(CRABC_TYPE_IS(__typeof__(&realpath),
    crabc_realpath_signature), "realpath declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&putenv), crabc_putenv_signature),
    "putenv declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&drand48), crabc_drand48_signature),
    "drand48 declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&posix_openpt),
    crabc_posix_openpt_signature), "posix_openpt declaration");
#endif

#if defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
typedef char *(*crabc_mktemp_signature)(char *);
typedef int (*crabc_mkstemps_signature)(char *, int);
typedef int (*crabc_mkostemps_signature)(char *, int, int);
typedef void *(*crabc_valloc_signature)(size_t);
typedef void *(*crabc_memalign_signature)(size_t, size_t);
typedef void *(*crabc_reallocarray_signature)(void *, size_t, size_t);
typedef void (*crabc_qsort_r_signature)(void *, size_t, size_t,
    int (*)(const void *, const void *, void *), void *);

_Static_assert(CRABC_TYPE_IS(__typeof__(&mktemp), crabc_mktemp_signature),
    "mktemp declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mkstemps),
    crabc_mkstemps_signature), "mkstemps declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mkostemps),
    crabc_mkostemps_signature), "mkostemps declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&valloc), crabc_valloc_signature),
    "valloc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&memalign), crabc_memalign_signature),
    "memalign declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&reallocarray),
    crabc_reallocarray_signature), "reallocarray declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&qsort_r), crabc_qsort_r_signature),
    "qsort_r declaration");
#endif

#if defined(CRABC_STDLIB_GNU)
typedef char *(*crabc_secure_getenv_signature)(const char *);
typedef int (*crabc_ptsname_r_signature)(int, char *, size_t);
struct __locale_struct;
typedef float (*crabc_strtof_l_signature)(const char *restrict,
    char **restrict, struct __locale_struct *);
typedef double (*crabc_strtod_l_signature)(const char *restrict,
    char **restrict, struct __locale_struct *);
typedef long double (*crabc_strtold_l_signature)(const char *restrict,
    char **restrict, struct __locale_struct *);

_Static_assert(CRABC_TYPE_IS(__typeof__(&secure_getenv),
    crabc_secure_getenv_signature), "secure_getenv declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ptsname_r),
    crabc_ptsname_r_signature), "ptsname_r declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtof_l),
    crabc_strtof_l_signature), "strtof_l declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtod_l),
    crabc_strtod_l_signature), "strtod_l declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtold_l),
    crabc_strtold_l_signature), "strtold_l declaration");
#endif

#endif /* !CRABC_STDLIB_HIDDEN_WITNESS_ONLY */

/*
 * A hidden-witness compile is correct only when this source fails because the
 * selected profile does not declare the named extension.  The runner first
 * establishes that behavior against musl, then treats a candidate success as
 * a header-profile mismatch instead of papering it over with a fallback.
 */
#if defined(CRABC_STDLIB_REQUIRE_POSIX_HIDDEN)
__attribute__((used)) static void *crabc_stdlib_posix_must_be_hidden =
    (void *)&setenv;
#endif

#if defined(CRABC_STDLIB_REQUIRE_XOPEN_HIDDEN)
__attribute__((used)) static void *crabc_stdlib_xopen_must_be_hidden =
    (void *)&realpath;
#endif

#if defined(CRABC_STDLIB_REQUIRE_GNU_BSD_HIDDEN)
__attribute__((used)) static void *crabc_stdlib_gnu_bsd_must_be_hidden =
    (void *)&reallocarray;
#endif

#if defined(CRABC_STDLIB_REQUIRE_GNU_ONLY_HIDDEN)
__attribute__((used)) static void *crabc_stdlib_gnu_only_must_be_hidden =
    (void *)&secure_getenv;
#endif

int crabc_x86_64_stdlib_header_abi_probe(void)
{
    return 0;
}
