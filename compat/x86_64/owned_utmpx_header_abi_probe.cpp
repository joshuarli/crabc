/* Installed-header C++17 witness for unmangled utmpx declarations. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <utmp.h>
#include <utmpx.h>

using utmpx_void_signature = void (*)(void);
using utmpx_cursor_signature = struct utmpx *(*)();
using utmpx_query_signature = struct utmpx *(*)(const struct utmpx *);
using utmpx_update_signature = void (*)(const char *, const struct utmpx *);
using utmpx_name_signature = int (*)(const char *);

#define ASSERT_VOID(symbol) \
    static_assert(__is_same(decltype(&(symbol)), utmpx_void_signature), \
        #symbol " declaration")
#define ASSERT_QUERY(symbol) \
    static_assert(__is_same(decltype(&(symbol)), utmpx_query_signature), \
        #symbol " declaration")
#define ASSERT_CURSOR(symbol) \
    static_assert(__is_same(decltype(&(symbol)), utmpx_cursor_signature), \
        #symbol " declaration")
#define ASSERT_UPDATE(symbol) \
    static_assert(__is_same(decltype(&(symbol)), utmpx_update_signature), \
        #symbol " declaration")
#define ASSERT_NAME(symbol) \
    static_assert(__is_same(decltype(&(symbol)), utmpx_name_signature), \
        #symbol " declaration")

ASSERT_VOID(endutxent);
ASSERT_VOID(setutxent);
ASSERT_CURSOR(getutxent);
ASSERT_QUERY(getutxid);
ASSERT_QUERY(getutxline);
ASSERT_QUERY(pututxline);
ASSERT_UPDATE(updwtmpx);
ASSERT_VOID(endutent);
ASSERT_VOID(setutent);
ASSERT_CURSOR(getutent);
ASSERT_QUERY(getutid);
ASSERT_QUERY(getutline);
ASSERT_QUERY(pututline);
ASSERT_UPDATE(updwtmp);
ASSERT_NAME(utmpname);
ASSERT_NAME(utmpxname);

extern "C" utmpx_void_signature crabc_x86_64_endutxent_header_cxx() { return endutxent; }
extern "C" utmpx_void_signature crabc_x86_64_setutxent_header_cxx() { return setutxent; }
extern "C" utmpx_cursor_signature crabc_x86_64_getutxent_header_cxx() { return getutxent; }
extern "C" utmpx_query_signature crabc_x86_64_getutxid_header_cxx() { return getutxid; }
extern "C" utmpx_query_signature crabc_x86_64_getutxline_header_cxx() { return getutxline; }
extern "C" utmpx_query_signature crabc_x86_64_pututxline_header_cxx() { return pututxline; }
extern "C" utmpx_update_signature crabc_x86_64_updwtmpx_header_cxx() { return updwtmpx; }
extern "C" utmpx_void_signature crabc_x86_64_endutent_header_cxx() { return endutent; }
extern "C" utmpx_void_signature crabc_x86_64_setutent_header_cxx() { return setutent; }
extern "C" utmpx_cursor_signature crabc_x86_64_getutent_header_cxx() { return getutent; }
extern "C" utmpx_query_signature crabc_x86_64_getutid_header_cxx() { return getutid; }
extern "C" utmpx_query_signature crabc_x86_64_getutline_header_cxx() { return getutline; }
extern "C" utmpx_query_signature crabc_x86_64_pututline_header_cxx() { return pututline; }
extern "C" utmpx_update_signature crabc_x86_64_updwtmp_header_cxx() { return updwtmp; }
extern "C" utmpx_name_signature crabc_x86_64_utmpname_header_cxx() { return utmpname; }
extern "C" utmpx_name_signature crabc_x86_64_utmpxname_header_cxx() { return utmpxname; }
