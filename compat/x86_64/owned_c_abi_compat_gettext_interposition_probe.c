/* A static consumer supplies musl's public gettext delegation targets. */
#include <libintl.h>
#include <string.h>

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

int main(void)
{
    return gettext("message") != singular
        || ngettext("one", "many", 1) != one
        || ngettext("one", "many", 2) != many;
}
