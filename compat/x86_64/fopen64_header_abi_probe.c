/* Linux/x86-64 <stdio.h> fopen64 large-file macro ABI probe.
 *
 * Pinned musl 1.2.6 is the public-header oracle.  This source deliberately
 * verifies only source-level LP64 aliasing: it does not request or imply an
 * ELF `fopen64` definition.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FOPEN64_HEADER_C11_BASE) + \
    defined(CRABC_FOPEN64_HEADER_C11_GNU) + \
    defined(CRABC_FOPEN64_HEADER_C11_FILE_OFFSET_BITS_64) + \
    defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE_SOURCE) + \
    defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE64)) != 1
#error "select exactly one C fopen64 header profile"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio.h>

#if defined(CRABC_FOPEN64_HEADER_C11_BASE)
#ifdef _LARGEFILE64_SOURCE
#error "base profile must not retain _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_C11_GNU)
#ifndef _GNU_SOURCE
#error "GNU profile must retain _GNU_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "GNU profile must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_C11_FILE_OFFSET_BITS_64)
#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error "_FILE_OFFSET_BITS=64 profile must retain its exact value"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "_FILE_OFFSET_BITS=64 must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE_SOURCE)
#ifndef _LARGEFILE_SOURCE
#error "large-file-source profile must retain _LARGEFILE_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "_LARGEFILE_SOURCE must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE64)
#ifndef _LARGEFILE64_SOURCE
#error "large-file profile must retain _LARGEFILE64_SOURCE"
#endif
#ifndef fopen64
#error "_LARGEFILE64_SOURCE must expose fopen64 as a macro alias"
#endif
#endif

#if !defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE64) && defined(fopen64)
#error "only _LARGEFILE64_SOURCE may expose the fopen64 macro alias"
#endif

typedef FILE *(*crabc_fopen64_signature)(const char *, const char *);

#define CRABC_FOPEN64_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)
_Static_assert(CRABC_FOPEN64_TYPE_IS(__typeof__(&fopen),
    crabc_fopen64_signature), "fopen declaration");

/* The LFS initializer must preprocess to an ordinary `fopen` reference.
 * The runner reads the resulting object and rejects an ELF `fopen64`
 * reference, making that source-level alias boundary observable in both
 * pinned musl and the project header. */
__attribute__((used)) static crabc_fopen64_signature volatile
    crabc_fopen_reference = &fopen;

#if defined(CRABC_FOPEN64_HEADER_C11_LARGEFILE64)
_Static_assert(CRABC_FOPEN64_TYPE_IS(__typeof__(&fopen64),
    crabc_fopen64_signature), "fopen64 macro declaration");
__attribute__((used)) static crabc_fopen64_signature volatile
    crabc_fopen64_macro_reference = &fopen64;
#endif

int crabc_x86_64_fopen64_header_abi_probe(void)
{
    return 0;
}
