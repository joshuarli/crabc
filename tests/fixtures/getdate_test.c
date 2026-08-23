#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int check_date(const struct tm *tm)
{
    return tm->tm_year == 124 && tm->tm_mon == 1 && tm->tm_mday == 29
        && tm->tm_hour == 0 && tm->tm_min == 0 && tm->tm_sec == 0;
}

int main(int argc, char **argv)
{
    struct tm *first;
    struct tm *second;

    if (argc != 2 || setenv("DATEMSK", argv[1], 1) != 0)
        return 1;

    first = getdate("2024-02-29");
    if (!first) {
        fprintf(stderr, "first getdate error %d\n", getdate_err);
        return 2;
    }
    if (!check_date(first)) {
        fprintf(stderr, "first getdate fields %d %d %d %d %d %d\n",
                first->tm_year, first->tm_mon, first->tm_mday,
                first->tm_hour, first->tm_min, first->tm_sec);
        return 2;
    }

    second = getdate("2024-02-29 12:34:56");
    if (!second || second != first
        || second->tm_year != 124 || second->tm_mon != 1 || second->tm_mday != 29
        || second->tm_hour != 12 || second->tm_min != 34 || second->tm_sec != 56)
        return 3;

    if (getdate("2024-02-29x") != NULL || getdate_err != 7) return 4;
    if (unsetenv("DATEMSK") != 0) return 5;
    if (getdate("2024-02-29") || getdate_err != 1) return 6;
    if (setenv("DATEMSK", "", 1) != 0) return 7;
    if (getdate("2024-02-29") || getdate_err != 2) return 8;
    if (setenv("DATEMSK", "/tmp/crabc-getdate-does-not-exist", 1) != 0) return 9;
    if (getdate("2024-02-29") || getdate_err != 2) return 10;

    puts("c-abi getdate ok");
    return 0;
}
