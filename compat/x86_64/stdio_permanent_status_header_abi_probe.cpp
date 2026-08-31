/* C++17 companion to the Linux/x86-64 permanent-stream status probe.
 *
 * `used` references let the runner prove that <stdio.h> requests C ABI
 * spellings. This remains declaration-only evidence for status predicates and
 * `clearerr`'s exact void return type.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_STATUS_CXX17)
#error "the C++17 permanent-stream-status profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

using crabc_stdio_status_predicate_signature = int (*)(FILE *);
using crabc_stdio_status_clear_signature = void (*)(FILE *);

static_assert(__is_same(decltype(&feof),
    crabc_stdio_status_predicate_signature), "feof C++ declaration");
static_assert(__is_same(decltype(&ferror),
    crabc_stdio_status_predicate_signature), "ferror C++ declaration");
static_assert(__is_same(decltype(&clearerr),
    crabc_stdio_status_clear_signature), "clearerr C++ declaration");

__attribute__((used)) static crabc_stdio_status_predicate_signature
    crabc_stdio_feof_reference = &feof;
__attribute__((used)) static crabc_stdio_status_predicate_signature
    crabc_stdio_ferror_reference = &ferror;
__attribute__((used)) static crabc_stdio_status_clear_signature
    crabc_stdio_clearerr_reference = &clearerr;

int crabc_x86_64_stdio_permanent_status_header_abi_probe_cpp()
{
    return 0;
}
