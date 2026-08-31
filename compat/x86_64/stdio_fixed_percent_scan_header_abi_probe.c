/* C11 declaration probe for the sealed literal-percent scanf artifact.
 *
 * This is declaration-only evidence for the existing `sscanf`/`vsscanf`
 * boundary. It neither links crabc-libc nor selects stream, locale, formatter,
 * or general stdio behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_C11)
#error "the C11 literal-percent scanf header profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdarg.h>
#include <stdio.h>

#define CRABC_STDIO_FIXED_PERCENT_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)
#define CRABC_STDIO_FIXED_PERCENT_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]

typedef int (*crabc_sscanf_signature)(const char *, const char *, ...);
typedef int (*crabc_vsscanf_signature)(const char *, const char *, va_list);

CRABC_STDIO_FIXED_PERCENT_ASSERT(crabc_sscanf_declaration,
    CRABC_STDIO_FIXED_PERCENT_TYPE_IS(__typeof__(&sscanf),
        crabc_sscanf_signature));
CRABC_STDIO_FIXED_PERCENT_ASSERT(crabc_vsscanf_declaration,
    CRABC_STDIO_FIXED_PERCENT_TYPE_IS(__typeof__(&vsscanf),
        crabc_vsscanf_signature));

int crabc_x86_64_stdio_fixed_percent_scan_header_abi_probe(void)
{
    return 0;
}
