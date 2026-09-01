/* C++ companion for the native x86-64 <ctype.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <ctype.h>

using ctype_signature = int (*)(int);

static_assert(__is_same(decltype(&isalnum), ctype_signature), "isalnum declaration");
static_assert(__is_same(decltype(&isalpha), ctype_signature), "isalpha declaration");
static_assert(__is_same(decltype(&isblank), ctype_signature), "isblank declaration");
static_assert(__is_same(decltype(&iscntrl), ctype_signature), "iscntrl declaration");
static_assert(__is_same(decltype(&isdigit), ctype_signature), "isdigit declaration");
static_assert(__is_same(decltype(&isgraph), ctype_signature), "isgraph declaration");
static_assert(__is_same(decltype(&islower), ctype_signature), "islower declaration");
static_assert(__is_same(decltype(&isprint), ctype_signature), "isprint declaration");
static_assert(__is_same(decltype(&ispunct), ctype_signature), "ispunct declaration");
static_assert(__is_same(decltype(&isspace), ctype_signature), "isspace declaration");
static_assert(__is_same(decltype(&isupper), ctype_signature), "isupper declaration");
static_assert(__is_same(decltype(&isxdigit), ctype_signature), "isxdigit declaration");
static_assert(__is_same(decltype(&tolower), ctype_signature), "tolower declaration");
static_assert(__is_same(decltype(&toupper), ctype_signature), "toupper declaration");
static_assert(__is_same(decltype(&isascii), ctype_signature), "isascii declaration");
static_assert(__is_same(decltype(&toascii), ctype_signature), "toascii declaration");
#ifdef isascii
#error "C++ must hide C-only isascii macro"
#endif
#ifndef _tolower
#error "_tolower must be visible in the native C++17 profile"
#endif
#ifndef _toupper
#error "_toupper must be visible in the native C++17 profile"
#endif
static_assert(_tolower('A') == 'a', "_tolower ASCII case bit");
static_assert(_toupper('a') == 'A', "_toupper ASCII case bit");
static_assert(_tolower(0x80) == 0xa0, "_tolower has musl bitwise behavior");
static_assert(_toupper(0x80) == 0, "_toupper has musl bitwise behavior");
static_assert(_tolower(-1) == -1, "_tolower does not validate EOF");
static_assert(_toupper(-1) == 0x5f, "_toupper does not validate EOF");
static_assert(__is_same(decltype(_tolower('A')), int), "_tolower result type");
static_assert(__is_same(decltype(_toupper('a')), int), "_toupper result type");

#if defined(CRABC_REQUIRE_C_FAST_CTYPE_HIDDEN)
#ifdef __isspace
#error "C++ must hide __isspace"
#endif
#if defined(isalpha) || defined(isdigit) || defined(islower) || \
    defined(isupper) || defined(isprint) || defined(isgraph) || defined(isspace)
#error "C++ must hide C-only ctype fast-path names"
#endif
#endif

int crabc_x86_64_ctype_header_abi_probe_cpp()
{
    return 0;
}
