/* Installed-header C++17 witness for unmangled utmpx declarations. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <utmpx.h>

using utmpx_void_signature = void (*)(void);
using utmpx_query_signature = struct utmpx *(*)(const struct utmpx *);
using utmpx_cursor_signature = struct utmpx *(*)();

static_assert(__is_same(decltype(&endutxent), utmpx_void_signature),
    "endutxent declaration");
static_assert(__is_same(decltype(&setutxent), utmpx_void_signature),
    "setutxent declaration");
static_assert(__is_same(decltype(&getutxent), utmpx_cursor_signature),
    "getutxent declaration");
static_assert(__is_same(decltype(&getutxid), utmpx_query_signature),
    "getutxid declaration");
static_assert(__is_same(decltype(&getutxline), utmpx_query_signature),
    "getutxline declaration");
static_assert(__is_same(decltype(&pututxline), utmpx_query_signature),
    "pututxline declaration");

extern "C" utmpx_void_signature crabc_x86_64_endutxent_header_cxx()
{
    return endutxent;
}

extern "C" utmpx_void_signature crabc_x86_64_setutxent_header_cxx()
{
    return setutxent;
}

extern "C" utmpx_cursor_signature crabc_x86_64_getutxent_header_cxx()
{
    return getutxent;
}

extern "C" utmpx_query_signature crabc_x86_64_getutxid_header_cxx()
{
    return getutxid;
}

extern "C" utmpx_query_signature crabc_x86_64_getutxline_header_cxx()
{
    return getutxline;
}

extern "C" utmpx_query_signature crabc_x86_64_pututxline_header_cxx()
{
    return pututxline;
}
