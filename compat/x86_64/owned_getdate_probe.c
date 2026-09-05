#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct tm *previous;

static int observe(const char *label, const char *input, int state)
{
    int saved, restored;
    if (pthread_setcancelstate(state, &saved)) return 1;
    errno = EDOM;
    struct tm *value = getdate(input);
    int error = errno;
    if (pthread_setcancelstate(saved, &restored) || restored != state) return 2;
    printf("%s result=%d getdate_err=%d errno=%d", label, value != 0, getdate_err, error);
    if (value) {
        printf(" same=%d tm=%d,%d,%d,%d,%d,%d,%d,%d,%d,%ld,%d",
            previous == 0 || previous == value, value->tm_sec, value->tm_min,
            value->tm_hour, value->tm_mday, value->tm_mon, value->tm_year,
            value->tm_wday, value->tm_yday, value->tm_isdst, value->tm_gmtoff,
            value->tm_zone == 0);
        previous = value;
    }
    putchar('\n');
    return 0;
}

static int template(const char *text)
{
    FILE *file = fopen("/templates/mask", "w");
    if (!file) return 1;
    int failed = fputs(text, file) < 0;
    return fclose(file) != 0 || failed;
}

int main(void)
{
    if (setvbuf(stdout, 0, _IONBF, 0)) return 1;
    if (unsetenv("DATEMSK")) return 2;
    getdate_err = 91;
    if (observe("unset", "2024", PTHREAD_CANCEL_DISABLE)) return 3;
    if (setenv("DATEMSK", "/templates/absent", 1)) return 4;
    if (observe("absent", "2024", PTHREAD_CANCEL_ENABLE)) return 5;
    if (setenv("DATEMSK", "/templates", 1)) return 6;
    if (observe("directory", "2024", PTHREAD_CANCEL_DISABLE)) return 7;
    if (setenv("DATEMSK", "/templates/mask", 1)) return 8;
    if (template("%Y-%m-%d %H:%M:%S\n")) return 9;
    if (observe("full", "2024-02-29 12:34:56", PTHREAD_CANCEL_ENABLE)) return 10;
    if (template("%Y\n")) return 11;
    if (observe("year", "2025", PTHREAD_CANCEL_DISABLE)) return 12;
    if (observe("suffix", "2026suffix", PTHREAD_CANCEL_ENABLE)) return 13;
    if (template("literal\n")) return 14;
    if (observe("retained-partial", "literal", PTHREAD_CANCEL_DISABLE)) return 15;
    if (template("%m\n%d\n")) return 16;
    if (observe("second-template", "29", PTHREAD_CANCEL_ENABLE)) return 17;
    if (template("")) return 18;
    if (observe("empty", "2024", PTHREAD_CANCEL_DISABLE)) return 19;
    if (template("%Y")) return 20;
    if (observe("unterminated-template", "2030", PTHREAD_CANCEL_ENABLE)) return 21;
    /* fgets' 100-byte buffer treats each chunk as a separate template. */
    char chunks[104];
    memset(chunks, 'x', 99);
    memcpy(chunks + 99, "%Y\n", 4);
    if (template(chunks)) return 22;
    if (observe("second-chunk", "2031", PTHREAD_CANCEL_DISABLE)) return 23;
    return 0;
}
