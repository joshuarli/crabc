/* Selected static x86 gettext/catalog no-catalog profile exercise. */

#include <errno.h>
#include <libintl.h>
#include <nl_types.h>

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
    "selected gettext/catalog C function signatures");

static int strings_equal(const char *left, const char *right)
{
    unsigned long index = 0;
    if (left == 0 || right == 0)
        return left == right;
    for (;;) {
        if (left[index] != right[index])
            return 0;
        if (left[index] == '\0')
            return 1;
        ++index;
    }
}

static int check_identity_fallback(void)
{
    static const char singular[] = "crabc singular";
    static const char plural[] = "crabc plural";

    errno = 71;
    if (gettext(singular) != singular || errno != 71)
        return 1;
    errno = 72;
    if (dgettext("other-domain", singular) != singular || errno != 72)
        return 2;
    errno = 73;
    if (dcgettext("other-domain", singular, 999) != singular || errno != 73)
        return 3;
    errno = 74;
    if (ngettext(singular, plural, 1UL) != singular || errno != 74)
        return 4;
    errno = 75;
    if (ngettext(singular, plural, 2UL) != plural || errno != 75)
        return 5;
    errno = 76;
    if (dngettext("other-domain", singular, plural, 1UL) != singular || errno != 76)
        return 6;
    errno = 77;
    if (dngettext("other-domain", singular, plural, 2UL) != plural || errno != 77)
        return 7;
    errno = 78;
    if (dcngettext(0, singular, plural, 1UL, -1) != singular || errno != 78)
        return 8;
    errno = 79;
    if (dcngettext(0, singular, plural, 2UL, -1) != plural || errno != 79)
        return 9;
    return 0;
}

static int check_domain_and_binding_state(void)
{
    static const char domain[] = "crabc-selected-domain";
    static const char directory_a[] = "/tmp/crabc-gettext-a";
    static const char directory_b[] = "/tmp/crabc-gettext-b";
    static const char missing_domain[] = "crabc-unbound-domain";
    char too_long_domain[257];
    char too_long_directory[4097];
    unsigned long index;

    if (!strings_equal(textdomain(0), "messages"))
        return 1;
    if (!strings_equal(textdomain(domain), domain) || !strings_equal(textdomain(0), domain))
        return 2;
    for (index = 0; index < 256; ++index)
        too_long_domain[index] = 'd';
    too_long_domain[256] = '\0';
    errno = 0;
    if (textdomain(too_long_domain) != 0 || errno != EINVAL ||
        !strings_equal(textdomain(0), domain))
        return 3;
    if (!strings_equal(textdomain(""), ""))
        return 4;
    if (!strings_equal(textdomain(domain), domain))
        return 5;

    errno = 63;
    if (bindtextdomain(0, directory_a) != 0 || errno != 63)
        return 6;
    errno = 64;
    if (bindtextdomain(missing_domain, 0) != 0 || errno != 64)
        return 7;
    if (!strings_equal(bindtextdomain(domain, directory_a), directory_a) ||
        !strings_equal(bindtextdomain(domain, 0), directory_a))
        return 8;
    if (!strings_equal(bindtextdomain(domain, directory_b), directory_b) ||
        !strings_equal(bindtextdomain(domain, 0), directory_b))
        return 9;
    for (index = 0; index < 4096; ++index)
        too_long_directory[index] = 'x';
    too_long_directory[4096] = '\0';
    errno = 0;
    if (bindtextdomain(domain, too_long_directory) != 0 || errno != EINVAL ||
        !strings_equal(bindtextdomain(domain, 0), directory_b))
        return 10;
    return 0;
}

static int check_codeset_and_missing_catalog(void)
{
    static const char fallback[] = "crabc catalog fallback";
    nl_catd catalog;

    errno = 41;
    if (!strings_equal(bind_textdomain_codeset("ignored", 0), "UTF-8") || errno != 41)
        return 1;
    errno = 42;
    if (!strings_equal(bind_textdomain_codeset("ignored", "uTf-8"), "UTF-8") || errno != 42)
        return 2;
    errno = 0;
    if (bind_textdomain_codeset("ignored", "UTF-16") != 0 || errno != EINVAL)
        return 3;

    errno = 0;
    catalog = catopen("/definitely-not-present/crabc-x86-catalog", NL_CAT_LOCALE);
    if (catalog != (nl_catd)-1 || errno != ENOENT)
        return 4;
#ifdef CRABC_GETTEXT_CATALOG_FREESTANDING
    if (catgets(catalog, 1, 1, fallback) != fallback)
        return 5;
    if (catclose(catalog) != 0)
        return 6;
#endif
    return 0;
}

#ifdef CRABC_GETTEXT_CATALOG_FREESTANDING
static int check_fixed_binding_capacity(void)
{
    static const char domain_one[] = "crabc-capacity-one";
    static const char domain_two[] = "crabc-capacity-two";
    static const char domain_three[] = "crabc-capacity-three";
    static const char directory_one[] = "/tmp/crabc-capacity-one";
    static const char directory_two[] = "/tmp/crabc-capacity-two";
    static const char directory_three[] = "/tmp/crabc-capacity-three";

    if (bindtextdomain(domain_one, directory_one) == 0 ||
        bindtextdomain(domain_two, directory_two) == 0)
        return 1;
    errno = 0;
    if (bindtextdomain(domain_three, directory_three) != 0 || errno != ENOMEM)
        return 2;
    if (!strings_equal(bindtextdomain("crabc-selected-domain", 0),
            "/tmp/crabc-gettext-b"))
        return 3;
    return 0;
}
#endif

int crabc_x86_64_gettext_catalog_probe(void)
{
    int result;
    result = check_identity_fallback();
    if (result != 0)
        return 10 + result;
    result = check_domain_and_binding_state();
    if (result != 0)
        return 30 + result;
    result = check_codeset_and_missing_catalog();
    if (result != 0)
        return 50 + result;
#ifdef CRABC_GETTEXT_CATALOG_FREESTANDING
    result = check_fixed_binding_capacity();
    if (result != 0)
        return 70 + result;
#endif
    return 0;
}

#ifndef CRABC_GETTEXT_CATALOG_FREESTANDING
int main(void)
{
    return crabc_x86_64_gettext_catalog_probe();
}
#endif
