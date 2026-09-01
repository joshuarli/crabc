/* Linux/x86-64 <libintl.h>/<nl_types.h> C++ linkage and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <libintl.h>
#include <nl_types.h>
#include <stddef.h>

#ifdef __fa
#error "musl's transient libintl format-argument annotation leaked"
#endif

static int crabc_gettext_format_argument_probe(const char *, ...)
    __attribute__((__format__(__printf__, 1, 2)));

#ifdef CRABC_REQUIRE_GETTEXT_FORMAT_ARGUMENT
static int crabc_gettext_format_argument_must_propagate()
{
    return crabc_gettext_format_argument_probe(gettext("%d"), "not an int");
}
#endif

using gettext_signature = char *(*)(const char *);
using dgettext_signature = char *(*)(const char *, const char *);
using dcgettext_signature = char *(*)(const char *, const char *, int);
using ngettext_signature = char *(*)(const char *, const char *, unsigned long);
using dngettext_signature = char *(*)(
    const char *, const char *, const char *, unsigned long);
using dcngettext_signature = char *(*)(
    const char *, const char *, const char *, unsigned long, int);
using textdomain_signature = char *(*)(const char *);
using bindtextdomain_signature = char *(*)(const char *, const char *);
using bind_textdomain_codeset_signature = char *(*)(const char *, const char *);
using catopen_signature = nl_catd (*)(const char *, int);
using catclose_signature = int (*)(nl_catd);
using catgets_signature = char *(*)(nl_catd, int, int, const char *);

static_assert(sizeof(nl_catd) == sizeof(void *) && alignof(nl_catd) == alignof(void *),
    "nl_catd is musl's pointer-sized opaque catalog handle");
static_assert(sizeof(nl_item) == 4 && alignof(nl_item) == 4,
    "nl_item is a four-byte int");
static_assert(NL_SETD == 1 && NL_CAT_LOCALE == 1,
    "selected message-catalog constants");
static_assert(__is_same(decltype(&gettext), gettext_signature) &&
    __is_same(decltype(&dgettext), dgettext_signature) &&
    __is_same(decltype(&dcgettext), dcgettext_signature) &&
    __is_same(decltype(&ngettext), ngettext_signature) &&
    __is_same(decltype(&dngettext), dngettext_signature) &&
    __is_same(decltype(&dcngettext), dcngettext_signature) &&
    __is_same(decltype(&textdomain), textdomain_signature) &&
    __is_same(decltype(&bindtextdomain), bindtextdomain_signature) &&
    __is_same(decltype(&bind_textdomain_codeset), bind_textdomain_codeset_signature) &&
    __is_same(decltype(&catopen), catopen_signature) &&
    __is_same(decltype(&catclose), catclose_signature) &&
    __is_same(decltype(&catgets), catgets_signature),
    "gettext/catalog declarations retain unmangled C ABI signatures");

static gettext_signature gettext_function __attribute__((used)) = gettext;
static dgettext_signature dgettext_function __attribute__((used)) = dgettext;
static dcgettext_signature dcgettext_function __attribute__((used)) = dcgettext;
static ngettext_signature ngettext_function __attribute__((used)) = ngettext;
static dngettext_signature dngettext_function __attribute__((used)) = dngettext;
static dcngettext_signature dcngettext_function __attribute__((used)) = dcngettext;
static textdomain_signature textdomain_function __attribute__((used)) = textdomain;
static bindtextdomain_signature bindtextdomain_function __attribute__((used)) = bindtextdomain;
static bind_textdomain_codeset_signature bind_textdomain_codeset_function
    __attribute__((used)) = bind_textdomain_codeset;
static catopen_signature catopen_function __attribute__((used)) = catopen;
static catclose_signature catclose_function __attribute__((used)) = catclose;
static catgets_signature catgets_function __attribute__((used)) = catgets;

int crabc_x86_64_gettext_catalog_header_abi_probe_cpp()
{
    return gettext_function != nullptr && dgettext_function != nullptr &&
        dcgettext_function != nullptr && ngettext_function != nullptr &&
        dngettext_function != nullptr && dcngettext_function != nullptr &&
        textdomain_function != nullptr && bindtextdomain_function != nullptr &&
        bind_textdomain_codeset_function != nullptr && catopen_function != nullptr &&
        catclose_function != nullptr && catgets_function != nullptr ? 0 : 1;
}
