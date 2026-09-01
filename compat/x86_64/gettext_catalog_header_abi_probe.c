/* Linux/x86-64 <libintl.h>/<nl_types.h> C declaration and ABI probe. */

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
static int crabc_gettext_format_argument_must_propagate(void)
{
    return crabc_gettext_format_argument_probe(gettext("%d"), "not an int");
}
#endif

typedef char *(*gettext_signature)(const char *);
typedef char *(*dgettext_signature)(const char *, const char *);
typedef char *(*dcgettext_signature)(const char *, const char *, int);
typedef char *(*ngettext_signature)(const char *, const char *, unsigned long);
typedef char *(*dngettext_signature)(
    const char *, const char *, const char *, unsigned long);
typedef char *(*dcngettext_signature)(
    const char *, const char *, const char *, unsigned long, int);
typedef char *(*textdomain_signature)(const char *);
typedef char *(*bindtextdomain_signature)(const char *, const char *);
typedef char *(*bind_textdomain_codeset_signature)(const char *, const char *);
typedef nl_catd (*catopen_signature)(const char *, int);
typedef int (*catclose_signature)(nl_catd);
typedef char *(*catgets_signature)(nl_catd, int, int, const char *);

_Static_assert(sizeof(nl_catd) == sizeof(void *) && _Alignof(nl_catd) == _Alignof(void *),
    "nl_catd is musl's pointer-sized opaque catalog handle");
_Static_assert(sizeof(nl_item) == 4 && _Alignof(nl_item) == 4,
    "nl_item is a four-byte int");
_Static_assert(NL_SETD == 1 && NL_CAT_LOCALE == 1,
    "selected message-catalog constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettext), gettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&dgettext), dgettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&dcgettext), dcgettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&ngettext), ngettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&dngettext), dngettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&dcngettext), dcngettext_signature) &&
    __builtin_types_compatible_p(__typeof__(&textdomain), textdomain_signature) &&
    __builtin_types_compatible_p(__typeof__(&bindtextdomain), bindtextdomain_signature) &&
    __builtin_types_compatible_p(__typeof__(&bind_textdomain_codeset),
        bind_textdomain_codeset_signature) &&
    __builtin_types_compatible_p(__typeof__(&catopen), catopen_signature) &&
    __builtin_types_compatible_p(__typeof__(&catclose), catclose_signature) &&
    __builtin_types_compatible_p(__typeof__(&catgets), catgets_signature),
    "gettext/catalog declarations retain exact C ABI signatures");

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

int crabc_x86_64_gettext_catalog_header_abi_probe(void)
{
    return gettext_function != 0 && dgettext_function != 0 &&
        dcgettext_function != 0 && ngettext_function != 0 &&
        dngettext_function != 0 && dcngettext_function != 0 &&
        textdomain_function != 0 && bindtextdomain_function != 0 &&
        bind_textdomain_codeset_function != 0 && catopen_function != 0 &&
        catclose_function != 0 && catgets_function != 0 ? 0 : 1;
}
