#define _GNU_SOURCE 1

#include <errno.h>
#include <fmtmsg.h>
#include <locale.h>
#include <monetary.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    char money[64] = {0};
    ssize_t length = strfmon(money, sizeof money, "%10.2n", 12.5);
    CHECK(length == 10, "strfmon length");
    CHECK(strcmp(money, "     12.50") == 0, "strfmon C formatting");

    length = strfmon(money, sizeof money, "%=*10.2n", 12.5);
    CHECK(length == 10 && strcmp(money, "     12.50") == 0,
          "strfmon fill flag");
    length = strfmon(money, sizeof money, "%-10.2n", 12.5);
    CHECK(length == 5 && strcmp(money, "12.50") == 0,
          "strfmon left flag");
    length = strfmon(money, sizeof money, "%10.2i", 12.5);
    CHECK(length == 10 && strcmp(money, "     12.50") == 0,
          "strfmon international conversion");
    length = strfmon(money, sizeof money, "%10.2c", 12.5);
    CHECK(length == 10 && strcmp(money, "     12.50") == 0,
          "strfmon conversion compatibility");

    locale_t c_locale = newlocale(LC_ALL_MASK, "C", NULL);
    CHECK(c_locale != (locale_t)0, "C locale");
    memset(money, 0, sizeof money);
    length = strfmon_l(money, sizeof money, c_locale, "%#6.3n", 12.5);
    CHECK(length == 10, "strfmon_l length");
    CHECK(strcmp(money, "    12.500") == 0, "strfmon_l C formatting");
    freelocale(c_locale);

    errno = 0;
    length = strfmon(money, 5, "%10.2n", 12.5);
    CHECK(length == -1 && errno == E2BIG, "strfmon E2BIG");
    CHECK(strfmon(money, 0, "%10.2n", 12.5) == 0, "strfmon zero size");

    CHECK(fmtmsg(0, "ignored", MM_ERROR, "ignored", NULL, NULL) == MM_OK,
          "fmtmsg no route");
    CHECK(setenv("MSGVERB", "label:severity:text:action:tag", 1) == 0,
          "MSGVERB setup");
    CHECK(fmtmsg(MM_PRINT, "LBL", MM_ERROR, "TEXT", "FIX", "TAG") == MM_OK,
          "fmtmsg print");
    CHECK(setenv("MSGVERB", "label:text", 1) == 0, "MSGVERB selection setup");
    CHECK(fmtmsg(MM_PRINT, "LBL", MM_INFO, "TEXT", "FIX", "TAG") == MM_OK,
          "fmtmsg MSGVERB selection");

    puts("m4 legacy formatting ok");
    return 0;
}
