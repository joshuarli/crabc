/* A static consumer supplies musl's public gettext delegation targets;
 * a dynamic DSO supplies the same targets to an ordinary consumer. */
#include <libintl.h>
#include <stdio.h>
#include <string.h>

#if !defined(CRABC_GETTEXT_DSO_CONSUMER)
static char singular[] = "application dgettext";
static char one[] = "application dngettext one";
static char many[] = "application dngettext many";

char *dgettext(const char *domain, const char *message)
{
    return domain == 0 && !strcmp(message, "message") ? singular : 0;
}

char *dngettext(const char *domain, const char *first, const char *second,
    unsigned long number)
{
    if (domain != 0 || strcmp(first, "one") || strcmp(second, "many"))
        return 0;
    return number == 1 ? one : many;
}
#endif

#if defined(CRABC_GETTEXT_DSO_CONSUMER)
int main(void)
{
    const char *direct = dgettext(0, "message");
    const char *direct_one = dngettext(0, "one", "many", 1);
    const char *direct_many = dngettext(0, "one", "many", 2);
    const char *through_gettext = gettext("message");
    const char *through_ngettext = ngettext("one", "many", 2);

    if (strcmp(direct, "application dgettext")
        || strcmp(direct_one, "application dngettext one")
        || strcmp(direct_many, "application dngettext many"))
        return 1;
    printf("gettext=%s\nngettext=%s\n", through_gettext, through_ngettext);
    return 0;
}
#elif !defined(CRABC_GETTEXT_DSO_PROVIDER)
int main(void)
{
    return gettext("message") != singular
        || ngettext("one", "many", 1) != one
        || ngettext("one", "many", 2) != many;
}
#endif
