/* C++17 companion for the Linux/x86-64 <stdio.h> fopen64 macro probe.
 *
 * It preserves musl's source-only LP64 alias contract and proves that the
 * alias keeps C linkage. It does not request an ELF `fopen64` spelling.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FOPEN64_HEADER_CXX17_BASE) + \
    defined(CRABC_FOPEN64_HEADER_CXX17_GNU) + \
    defined(CRABC_FOPEN64_HEADER_CXX17_FILE_OFFSET_BITS_64) + \
    defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE_SOURCE) + \
    defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE64)) != 1
#error "select exactly one C++ fopen64 header profile"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

#if defined(CRABC_FOPEN64_HEADER_CXX17_BASE)
#ifdef _LARGEFILE64_SOURCE
#error "base profile must not retain _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_CXX17_GNU)
#ifndef _GNU_SOURCE
#error "GNU profile must retain _GNU_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "GNU profile must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_CXX17_FILE_OFFSET_BITS_64)
#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error "_FILE_OFFSET_BITS=64 profile must retain its exact value"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "_FILE_OFFSET_BITS=64 must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE_SOURCE)
#ifndef _LARGEFILE_SOURCE
#error "large-file-source profile must retain _LARGEFILE_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "_LARGEFILE_SOURCE must not select _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE64)
#ifndef _LARGEFILE64_SOURCE
#error "large-file profile must retain _LARGEFILE64_SOURCE"
#endif
#ifndef fopen64
#error "_LARGEFILE64_SOURCE must expose fopen64 as a macro alias"
#endif
#endif

#if !defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE64) && defined(fopen64)
#error "only _LARGEFILE64_SOURCE may expose the fopen64 macro alias"
#endif

using crabc_fopen64_signature = FILE *(*)(const char *, const char *);
static_assert(__is_same(decltype(&fopen), crabc_fopen64_signature),
    "fopen C++ declaration");

__attribute__((used)) static crabc_fopen64_signature volatile
    crabc_fopen_reference = &fopen;

#if defined(CRABC_FOPEN64_HEADER_CXX17_LARGEFILE64)
static_assert(__is_same(decltype(&fopen64), crabc_fopen64_signature),
    "fopen64 C++ macro declaration");
__attribute__((used)) static crabc_fopen64_signature volatile
    crabc_fopen64_macro_reference = &fopen64;
#endif
