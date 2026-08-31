/* C++17 companion for the bounded LP64 tmpfile header alias.
 *
 * This compile-only probe deliberately covers only tmpfile64's macro/type
 * identity. It is not the wider stdio LFS declaration matrix.
 */

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

#ifndef tmpfile64
#error "Linux LP64 must expose tmpfile64 as a preprocessing alias"
#endif

using crabc_tmpfile_signature = FILE *(*)(void);
static_assert(__is_same(decltype(&tmpfile), crabc_tmpfile_signature),
    "tmpfile C++ declaration");
static_assert(__is_same(decltype(&tmpfile64), crabc_tmpfile_signature),
    "tmpfile64 macro declaration");

__attribute__((used)) static crabc_tmpfile_signature
    crabc_tmpfile_reference = &tmpfile;
__attribute__((used)) static crabc_tmpfile_signature
    crabc_tmpfile64_reference = &tmpfile64;
