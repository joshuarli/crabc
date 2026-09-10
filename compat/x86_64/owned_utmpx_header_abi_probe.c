/* Installed-header C witness for the bounded native utmpx ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <utmpx.h>

typedef void (*utmpx_void_signature)(void);
typedef struct utmpx *(*utmpx_query_signature)(const struct utmpx *);
typedef struct utmpx *(*utmpx_cursor_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&endutxent),
    utmpx_void_signature), "endutxent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setutxent),
    utmpx_void_signature), "setutxent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getutxent),
    utmpx_cursor_signature), "getutxent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getutxid),
    utmpx_query_signature), "getutxid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getutxline),
    utmpx_query_signature), "getutxline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pututxline),
    utmpx_query_signature), "pututxline declaration");

/* Keep direct external C references in this common object. */
utmpx_void_signature crabc_x86_64_endutxent_header_c(void) { return endutxent; }
utmpx_void_signature crabc_x86_64_setutxent_header_c(void) { return setutxent; }
utmpx_cursor_signature crabc_x86_64_getutxent_header_c(void) { return getutxent; }
utmpx_query_signature crabc_x86_64_getutxid_header_c(void) { return getutxid; }
utmpx_query_signature crabc_x86_64_getutxline_header_c(void) { return getutxline; }
utmpx_query_signature crabc_x86_64_pututxline_header_c(void) { return pututxline; }
