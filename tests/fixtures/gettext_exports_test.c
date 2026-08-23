#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

static int check_identity_and_plural(void)
{
    if (strcmp(gettext("hello"), "hello") != 0)
        return 1;
    if (strcmp(dgettext("missing-domain", "world"), "world") != 0)
        return 2;
    if (strcmp(dcgettext("missing-domain", "catalog", LC_MESSAGES), "catalog") != 0)
        return 3;
    if (strcmp(ngettext("one file", "many files", 1), "one file") != 0)
        return 4;
    if (strcmp(ngettext("one file", "many files", 0), "many files") != 0)
        return 5;
    if (strcmp(dngettext("missing-domain", "one item", "many items", 2), "many items") != 0)
        return 6;
    if (strcmp(dcngettext("missing-domain", "one entry", "many entries", 1, LC_MESSAGES),
               "one entry") != 0)
        return 7;
    if (strcmp(dcngettext("missing-domain", "one entry", "many entries", 3, LC_MESSAGES),
               "many entries") != 0)
        return 8;
    return 0;
}

static int check_domain_and_binding_state(void)
{
    char *domain;
    char *bound;
    char long_domain[257];
    char long_dir[4097];

    domain = textdomain(NULL);
    if (!domain || strcmp(domain, "messages") != 0)
        return 1;
    domain = textdomain("crabc-gettext-domain");
    if (!domain || strcmp(domain, "crabc-gettext-domain") != 0 ||
        textdomain(NULL) != domain)
        return 2;

    if (bindtextdomain(NULL, "/tmp") != NULL)
        return 3;
    if (bindtextdomain("crabc-gettext-domain", NULL) != NULL)
        return 4;
    bound = bindtextdomain("crabc-gettext-domain", "/tmp/crabc-gettext-a");
    if (!bound || strcmp(bound, "/tmp/crabc-gettext-a") != 0)
        return 5;
    if (bindtextdomain("crabc-gettext-domain", NULL) != bound ||
        strcmp(bindtextdomain("crabc-gettext-domain", NULL),
               "/tmp/crabc-gettext-a") != 0)
        return 6;

    // Rebinding selects the new directory and leaves the old allocation
    // untouched, which is observable through the returned query pointer.
    bound = bindtextdomain("crabc-gettext-domain", "/tmp/crabc-gettext-b");
    if (!bound || strcmp(bound, "/tmp/crabc-gettext-b") != 0 ||
        strcmp(bindtextdomain("crabc-gettext-domain", NULL),
               "/tmp/crabc-gettext-b") != 0)
        return 7;
    bound = bindtextdomain("crabc-gettext-domain", "/tmp/crabc-gettext-a");
    if (!bound || strcmp(bound, "/tmp/crabc-gettext-a") != 0 ||
        strcmp(bindtextdomain("crabc-gettext-domain", NULL),
               "/tmp/crabc-gettext-a") != 0)
        return 8;
    if (bindtextdomain("other-domain", NULL) != NULL)
        return 9;

    memset(long_domain, 'd', sizeof long_domain - 1);
    long_domain[sizeof long_domain - 1] = '\0';
    errno = 0;
    if (textdomain(long_domain) != NULL || errno != EINVAL ||
        strcmp(textdomain(NULL), "crabc-gettext-domain") != 0)
        return 10;
    memset(long_dir, 'p', sizeof long_dir - 1);
    long_dir[sizeof long_dir - 1] = '\0';
    errno = 0;
    if (bindtextdomain("crabc-gettext-domain", long_dir) != NULL || errno != EINVAL)
        return 11;

    if (!bind_textdomain_codeset("crabc-gettext-domain", NULL) ||
        strcmp(bind_textdomain_codeset("crabc-gettext-domain", NULL), "UTF-8") != 0)
        return 12;
    if (!bind_textdomain_codeset("crabc-gettext-domain", "uTf-8") ||
        strcmp(bind_textdomain_codeset("crabc-gettext-domain", "uTf-8"), "UTF-8") != 0)
        return 13;
    errno = 0;
    if (bind_textdomain_codeset("crabc-gettext-domain", "ASCII") != NULL ||
        errno != EINVAL)
        return 14;
    return 0;
}

int main(void)
{
    int result = check_identity_and_plural();
    if (result)
        return result;
    result = check_domain_and_binding_state();
    if (result)
        return 20 + result;
    puts("c-abi gettext exports ok");
    return 0;
}
