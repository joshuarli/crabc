/* Installed-header C witness for the complete native utmpx ABI boundary. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <utmp.h>
#include <utmpx.h>

typedef void (*utmpx_void_signature)(void);
typedef struct utmpx *(*utmpx_cursor_signature)(void);
typedef struct utmpx *(*utmpx_query_signature)(const struct utmpx *);
typedef void (*utmpx_update_signature)(const char *, const struct utmpx *);
typedef int (*utmpx_name_signature)(const char *);

#define ASSERT_VOID(symbol) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(symbol)), \
        utmpx_void_signature), #symbol " declaration")
#define ASSERT_QUERY(symbol) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(symbol)), \
        utmpx_query_signature), #symbol " declaration")
#define ASSERT_CURSOR(symbol) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(symbol)), \
        utmpx_cursor_signature), #symbol " declaration")
#define ASSERT_UPDATE(symbol) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(symbol)), \
        utmpx_update_signature), #symbol " declaration")
#define ASSERT_NAME(symbol) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(symbol)), \
        utmpx_name_signature), #symbol " declaration")

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

/* Keep direct external C references in this common object. */
utmpx_void_signature crabc_x86_64_endutxent_header_c(void) { return endutxent; }
utmpx_void_signature crabc_x86_64_setutxent_header_c(void) { return setutxent; }
utmpx_cursor_signature crabc_x86_64_getutxent_header_c(void) { return getutxent; }
utmpx_query_signature crabc_x86_64_getutxid_header_c(void) { return getutxid; }
utmpx_query_signature crabc_x86_64_getutxline_header_c(void) { return getutxline; }
utmpx_query_signature crabc_x86_64_pututxline_header_c(void) { return pututxline; }
utmpx_update_signature crabc_x86_64_updwtmpx_header_c(void) { return updwtmpx; }
utmpx_void_signature crabc_x86_64_endutent_header_c(void) { return endutent; }
utmpx_void_signature crabc_x86_64_setutent_header_c(void) { return setutent; }
utmpx_cursor_signature crabc_x86_64_getutent_header_c(void) { return getutent; }
utmpx_query_signature crabc_x86_64_getutid_header_c(void) { return getutid; }
utmpx_query_signature crabc_x86_64_getutline_header_c(void) { return getutline; }
utmpx_query_signature crabc_x86_64_pututline_header_c(void) { return pututline; }
utmpx_update_signature crabc_x86_64_updwtmp_header_c(void) { return updwtmp; }
utmpx_name_signature crabc_x86_64_utmpname_header_c(void) { return utmpname; }
utmpx_name_signature crabc_x86_64_utmpxname_header_c(void) { return utmpxname; }
