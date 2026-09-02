/* C++17 companion for the x86 stateful byte-string declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>
#include <string.h>

using dirname_signature = char *(*)(char *);
using strcasestr_signature = char *(*)(const char *, const char *);
using strtok_r_signature = char *(*)(char *, const char *, char **);

static_assert(__is_same(decltype(&dirname), dirname_signature), "dirname declaration");
static_assert(__is_same(decltype(&strcasestr), strcasestr_signature),
              "strcasestr declaration");
static_assert(__is_same(decltype(&strtok_r), strtok_r_signature),
              "strtok_r declaration");

static dirname_signature dirname_function __attribute__((used)) = dirname;
static strcasestr_signature strcasestr_function __attribute__((used)) = strcasestr;
static strtok_r_signature strtok_r_function __attribute__((used)) = strtok_r;

int crabc_x86_64_stateful_byte_strings_header_abi_probe_cpp()
{
    return dirname_function != nullptr && strcasestr_function != nullptr &&
                   strtok_r_function != nullptr
               ? 0
               : 1;
}
