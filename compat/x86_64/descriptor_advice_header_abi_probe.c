/* Linux/x86-64 <fcntl.h> descriptor-advice declaration/profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_DESCRIPTOR_ADVICE_STRICT) + \
    defined(CRABC_DESCRIPTOR_ADVICE_GNU) + \
    defined(CRABC_DESCRIPTOR_ADVICE_LARGEFILE64)) != 1
#error "select exactly one descriptor-advice header profile"
#endif

#include <fcntl.h>

_Static_assert(sizeof(off_t) == 8 && (off_t)-1 < 0,
    "x86 signed 64-bit off_t");
_Static_assert(POSIX_FADV_NORMAL == 0 && POSIX_FADV_RANDOM == 1 &&
    POSIX_FADV_SEQUENTIAL == 2 && POSIX_FADV_WILLNEED == 3 &&
    POSIX_FADV_DONTNEED == 4 && POSIX_FADV_NOREUSE == 5,
    "x86 POSIX file-advice values");

typedef int (*posix_fadvise_signature)(int, off_t, off_t, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_fadvise),
    posix_fadvise_signature), "posix_fadvise declaration");

#if defined(CRABC_DESCRIPTOR_ADVICE_STRICT)
#ifdef _GNU_SOURCE
#error "strict posix_fadvise profile must not select GNU declarations"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "strict posix_fadvise profile must not select large-file aliases"
#endif
#ifdef posix_fadvise64
#error "strict profile must not expose the posix_fadvise64 macro alias"
#endif
#ifdef readahead
#error "strict profile must not expose a readahead macro"
#endif
#endif

#if defined(CRABC_DESCRIPTOR_ADVICE_GNU)
#ifndef _GNU_SOURCE
#error "GNU readahead profile must select _GNU_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "GNU-only readahead profile must not select large-file aliases"
#endif
#ifdef posix_fadvise64
#error "GNU-only profile must not expose the posix_fadvise64 macro alias"
#endif
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8 &&
    (ssize_t)-1 < 0, "x86 GNU readahead LP64 scalar types");
typedef ssize_t (*readahead_signature)(int, off_t, size_t);
_Static_assert(__builtin_types_compatible_p(__typeof__(&readahead),
    readahead_signature), "GNU readahead declaration");
#endif

#if defined(CRABC_DESCRIPTOR_ADVICE_LARGEFILE64)
#ifdef _GNU_SOURCE
#error "large-file-only posix_fadvise profile must not select GNU declarations"
#endif
#ifndef _LARGEFILE64_SOURCE
#error "large-file posix_fadvise profile must select _LARGEFILE64_SOURCE"
#endif
#ifndef posix_fadvise64
#error "large-file profile must expose the posix_fadvise64 macro alias"
#endif
#ifdef readahead
#error "large-file-only profile must not expose a readahead macro"
#endif
_Static_assert(sizeof(off64_t) == 8 && sizeof(off64_t) == sizeof(off_t) &&
    (off64_t)-1 < 0, "x86 signed 64-bit large-file off64_t");
typedef int (*posix_fadvise64_signature)(int, off64_t, off64_t, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_fadvise64),
    posix_fadvise64_signature), "posix_fadvise64 macro declaration");
#endif

/* The runner opts into this reference only for profiles where GNU must hide
 * `readahead`. A failed compile is the visibility proof; no implicit-C
 * declaration fallback can turn an address-of undeclared identifier valid. */
#if defined(CRABC_DESCRIPTOR_ADVICE_REQUIRE_READAHEAD_HIDDEN)
__attribute__((used)) static void *descriptor_advice_readahead_must_be_hidden =
    (void *)&readahead;
#endif

int crabc_x86_64_descriptor_advice_header_abi_probe(void)
{
    return 0;
}
