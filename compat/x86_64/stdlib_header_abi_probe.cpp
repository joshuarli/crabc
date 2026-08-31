/*
 * C++17 companion to the Linux/x86-64 <stdlib.h> feature-profile probe.
 *
 * The normal pass emits references to selected declarations so the runner can
 * inspect their linkage.  A separate null-witness pass proves musl's C++11+
 * `NULL` contract without preventing ordinary candidate linkage inspection.
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

#if (defined(CRABC_STDLIB_INCLUDE_STDIO_FIRST) + \
    defined(CRABC_STDLIB_INCLUDE_STRING_FIRST)) > 1
#error "select at most one C++ null-witness include order"
#endif

#if defined(CRABC_STDLIB_INCLUDE_STDIO_FIRST)
#include <stdio.h>
#if defined(CRABC_STDLIB_REQUIRE_CPP_NULLPTR)
static_assert(__is_same(decltype(NULL), decltype(nullptr)),
    "musl C++17 stdio.h NULL is nullptr before stdlib.h");
#endif
#include <stdlib.h>
#elif defined(CRABC_STDLIB_INCLUDE_STRING_FIRST)
#include <string.h>
#if defined(CRABC_STDLIB_REQUIRE_CPP_NULLPTR)
static_assert(__is_same(decltype(NULL), decltype(nullptr)),
    "musl C++17 string.h NULL is nullptr before stdlib.h");
#endif
#include <stdlib.h>
#else
#include <stdlib.h>
#endif

#if !defined(CRABC_STDLIB_HIDDEN_WITNESS_ONLY) && \
    !defined(CRABC_STDLIB_NULL_WITNESS_ONLY)
using crabc_malloc_signature = void *(*)(size_t);
using crabc_strtol_signature = long (*)(const char *__restrict,
    char **__restrict, int);
using crabc_qsort_signature = void (*)(void *, size_t, size_t,
    int (*)(const void *, const void *));
using crabc_getenv_signature = char *(*)(const char *);

static_assert(__is_same(decltype(&malloc), crabc_malloc_signature),
    "malloc C++ declaration");
static_assert(__is_same(decltype(&strtol), crabc_strtol_signature),
    "strtol C++ declaration");
static_assert(__is_same(decltype(&qsort), crabc_qsort_signature),
    "qsort C++ declaration");
static_assert(__is_same(decltype(&getenv), crabc_getenv_signature),
    "getenv C++ declaration");
static_assert(sizeof(div_t) == 2 * sizeof(int) &&
    alignof(div_t) == alignof(int), "LP64 div_t ABI");
static_assert(sizeof(ldiv_t) == 2 * sizeof(long) &&
    alignof(ldiv_t) == alignof(long), "LP64 ldiv_t ABI");
static_assert(sizeof(lldiv_t) == 2 * sizeof(long long) &&
    alignof(lldiv_t) == alignof(long long), "LP64 lldiv_t ABI");

#if defined(CRABC_STDLIB_STRICT)
#if defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || \
    defined(_BSD_SOURCE) || defined(_LARGEFILE64_SOURCE)
#error "strict C++17 must not select a POSIX, X/Open, GNU, BSD, or LFS profile"
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
static_assert(WNOHANG == 1 && WUNTRACED == 2,
    "musl wait option values");
static_assert(WEXITSTATUS(0x1234) == 0x12 && WTERMSIG(0x127f) == 0x7f &&
    WSTOPSIG(0x137f) == 0x13, "musl wait-status extraction");
static_assert(WIFEXITED(0x1200) && !WIFEXITED(0x127f),
    "musl WIFEXITED status partition");
static_assert(!WIFSTOPPED(0x007f),
    "musl WIFSTOPPED rejects a stop status with no stopping signal");
static_assert(WIFSTOPPED(0x137f),
    "musl WIFSTOPPED accepts a stopped child status");
static_assert(WIFSIGNALED(0x0009) && WIFSIGNALED(0x007f) &&
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
static_assert(WIFCONTINUED(0xffff), "musl WIFCONTINUED true status");
static_assert(WCOREDUMP(0x80), "musl WCOREDUMP core-bit status");
#else
#if defined(WIFCONTINUED) || defined(WCOREDUMP)
#error "non-GNU/BSD profiles must hide musl WIFCONTINUED and WCOREDUMP"
#endif
#endif

/* `used` preserves each reference for the runner's C-linkage ELF check. */
__attribute__((used)) static crabc_malloc_signature crabc_stdlib_cxx_malloc =
    &malloc;
__attribute__((used)) static crabc_strtol_signature crabc_stdlib_cxx_strtol =
    &strtol;
__attribute__((used)) static crabc_qsort_signature crabc_stdlib_cxx_qsort =
    &qsort;
__attribute__((used)) static crabc_getenv_signature crabc_stdlib_cxx_getenv =
    &getenv;

#if defined(CRABC_STDLIB_POSIX_2008) || \
    defined(CRABC_STDLIB_XOPEN_700) || \
    defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
using crabc_setenv_signature = int (*)(const char *, const char *, int);
using crabc_unsetenv_signature = int (*)(const char *);
using crabc_rand_r_signature = int (*)(unsigned *);

static_assert(__is_same(decltype(&setenv), crabc_setenv_signature),
    "setenv C++ declaration");
static_assert(__is_same(decltype(&unsetenv), crabc_unsetenv_signature),
    "unsetenv C++ declaration");
static_assert(__is_same(decltype(&rand_r), crabc_rand_r_signature),
    "rand_r C++ declaration");
__attribute__((used)) static crabc_setenv_signature crabc_stdlib_cxx_setenv =
    &setenv;
__attribute__((used)) static crabc_unsetenv_signature
    crabc_stdlib_cxx_unsetenv = &unsetenv;
__attribute__((used)) static crabc_rand_r_signature crabc_stdlib_cxx_rand_r =
    &rand_r;
#endif

#if defined(CRABC_STDLIB_XOPEN_700) || \
    defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
using crabc_realpath_signature = char *(*)(const char *__restrict,
    char *__restrict);
using crabc_putenv_signature = int (*)(char *);
using crabc_drand48_signature = double (*)(void);

static_assert(__is_same(decltype(&realpath), crabc_realpath_signature),
    "realpath C++ declaration");
static_assert(__is_same(decltype(&putenv), crabc_putenv_signature),
    "putenv C++ declaration");
static_assert(__is_same(decltype(&drand48), crabc_drand48_signature),
    "drand48 C++ declaration");
__attribute__((used)) static crabc_realpath_signature
    crabc_stdlib_cxx_realpath = &realpath;
__attribute__((used)) static crabc_putenv_signature crabc_stdlib_cxx_putenv =
    &putenv;
__attribute__((used)) static crabc_drand48_signature crabc_stdlib_cxx_drand48 =
    &drand48;
#endif

#if defined(CRABC_STDLIB_GNU) || defined(CRABC_STDLIB_BSD)
using crabc_mktemp_signature = char *(*)(char *);
using crabc_mkstemps_signature = int (*)(char *, int);
using crabc_mkostemps_signature = int (*)(char *, int, int);
using crabc_valloc_signature = void *(*)(size_t);
using crabc_memalign_signature = void *(*)(size_t, size_t);
using crabc_reallocarray_signature = void *(*)(void *, size_t, size_t);
using crabc_qsort_r_signature = void (*)(void *, size_t, size_t,
    int (*)(const void *, const void *, void *), void *);
using crabc_clearenv_signature = int (*)(void);

static_assert(__is_same(decltype(&mktemp), crabc_mktemp_signature),
    "mktemp C++ declaration");
static_assert(__is_same(decltype(&mkstemps), crabc_mkstemps_signature),
    "mkstemps C++ declaration");
static_assert(__is_same(decltype(&mkostemps), crabc_mkostemps_signature),
    "mkostemps C++ declaration");
static_assert(__is_same(decltype(&valloc), crabc_valloc_signature),
    "valloc C++ declaration");
static_assert(__is_same(decltype(&memalign), crabc_memalign_signature),
    "memalign C++ declaration");
static_assert(__is_same(decltype(&reallocarray),
    crabc_reallocarray_signature), "reallocarray C++ declaration");
static_assert(__is_same(decltype(&qsort_r), crabc_qsort_r_signature),
    "qsort_r C++ declaration");
static_assert(__is_same(decltype(&clearenv), crabc_clearenv_signature),
    "clearenv C++ declaration");
__attribute__((used)) static crabc_mktemp_signature
    crabc_stdlib_cxx_mktemp = &mktemp;
__attribute__((used)) static crabc_mkstemps_signature
    crabc_stdlib_cxx_mkstemps = &mkstemps;
__attribute__((used)) static crabc_mkostemps_signature
    crabc_stdlib_cxx_mkostemps = &mkostemps;
__attribute__((used)) static crabc_valloc_signature
    crabc_stdlib_cxx_valloc = &valloc;
__attribute__((used)) static crabc_memalign_signature
    crabc_stdlib_cxx_memalign = &memalign;
__attribute__((used)) static crabc_reallocarray_signature
    crabc_stdlib_cxx_reallocarray = &reallocarray;
__attribute__((used)) static crabc_qsort_r_signature
    crabc_stdlib_cxx_qsort_r = &qsort_r;
__attribute__((used)) static crabc_clearenv_signature
    crabc_stdlib_cxx_clearenv = &clearenv;
#endif

#if defined(CRABC_STDLIB_GNU)
using crabc_secure_getenv_signature = char *(*)(const char *);
struct __locale_struct;
using crabc_strtof_l_signature = float (*)(const char *__restrict,
    char **__restrict, struct __locale_struct *);
using crabc_strtod_l_signature = double (*)(const char *__restrict,
    char **__restrict, struct __locale_struct *);
using crabc_strtold_l_signature = long double (*)(const char *__restrict,
    char **__restrict, struct __locale_struct *);

static_assert(__is_same(decltype(&secure_getenv),
    crabc_secure_getenv_signature), "secure_getenv C++ declaration");
static_assert(__is_same(decltype(&strtof_l), crabc_strtof_l_signature),
    "strtof_l C++ declaration");
static_assert(__is_same(decltype(&strtod_l), crabc_strtod_l_signature),
    "strtod_l C++ declaration");
static_assert(__is_same(decltype(&strtold_l), crabc_strtold_l_signature),
    "strtold_l C++ declaration");
__attribute__((used)) static crabc_secure_getenv_signature
    crabc_stdlib_cxx_secure_getenv = &secure_getenv;
__attribute__((used)) static crabc_strtof_l_signature
    crabc_stdlib_cxx_strtof_l = &strtof_l;
__attribute__((used)) static crabc_strtod_l_signature
    crabc_stdlib_cxx_strtod_l = &strtod_l;
__attribute__((used)) static crabc_strtold_l_signature
    crabc_stdlib_cxx_strtold_l = &strtold_l;
#endif

#endif /* ordinary, non-witness profile contract */

/*
 * Musl deliberately gives C++11-and-newer callers the language-native null
 * pointer.  This is compiled separately so a null mismatch is reported next
 * to, rather than obscuring, the ordinary C-linkage witness.  The runner also
 * suppresses ordinary profile declarations here so a known unrelated missing
 * extension cannot conceal a NULL regression.
 */
#if defined(CRABC_STDLIB_REQUIRE_CPP_NULLPTR)
static_assert(__is_same(decltype(NULL), decltype(nullptr)),
    "musl C++17 NULL is nullptr");
#endif

/* See the C source for the expected-failure hidden-profile witnesses. */
#if defined(CRABC_STDLIB_REQUIRE_POSIX_HIDDEN)
__attribute__((used)) static auto crabc_stdlib_posix_must_be_hidden = &setenv;
#endif

#if defined(CRABC_STDLIB_REQUIRE_XOPEN_HIDDEN)
__attribute__((used)) static auto crabc_stdlib_xopen_must_be_hidden =
    &realpath;
#endif

#if defined(CRABC_STDLIB_REQUIRE_GNU_BSD_HIDDEN)
__attribute__((used)) static auto crabc_stdlib_gnu_bsd_must_be_hidden =
    &reallocarray;
#endif

#if defined(CRABC_STDLIB_REQUIRE_GNU_ONLY_HIDDEN)
__attribute__((used)) static auto crabc_stdlib_gnu_only_must_be_hidden =
    &secure_getenv;
#endif

int crabc_x86_64_stdlib_header_abi_probe_cpp()
{
    return 0;
}
