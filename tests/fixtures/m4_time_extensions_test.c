#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <time.h>

int main(void)
{
    struct timespec now = { -1, -1 };
    struct timespec unchanged = { 7, 11 };
    struct tm calendar = { 0 };
    char formatted[32];

    if (timespec_get(&now, TIME_UTC) != TIME_UTC || now.tv_sec <= 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000L)
        return 1;
    if (timespec_get(&unchanged, 99) != 0 || unchanged.tv_sec != 7 ||
        unchanged.tv_nsec != 11)
        return 2;
    calendar.tm_year = 124;
    calendar.tm_mon = 0;
    calendar.tm_mday = 2;
    if (strftime_l(formatted, sizeof formatted, "%Y-%m-%d", &calendar, NULL) != 10 ||
        strcmp(formatted, "2024-01-02") != 0)
        return 3;
    puts("m4 time extensions ok");
    return 0;
}
