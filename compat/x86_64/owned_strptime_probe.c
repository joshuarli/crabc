#define _GNU_SOURCE 1
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* Every record exposes the unconsumed suffix, touched and untouched tm fields,
 * and errno, including partial writes on failure. The object is shared by the
 * pinned musl reference and every installed candidate entry. */
static const struct { const char *input; const char *format; } cases[] = {
    { "2024-02-29tail", "%F" }, { " 2024-02-29", "%F" },
    { "+002024-02-29tail", "%F" }, { "-0000044-03-15tail", "%F" },
    { "2024-02-29tail", "%10F" }, { "2024-02-29tail", "%9F" },
    { "12345-01-02tail", "%F" }, { "12345tail", "%Y" },
    { "12345tail", "%5Y" }, { "2024tail", "%0Y" },
    { "-0044tail", "%Y" }, { "+2024tail", "%+Y" },
    { "20 68", "%C %y" }, { "68 20", "%y %C" },
    { "68", "%y" }, { "69", "%y" }, { "20", "%C" },
    { "20 99 2024", "%C %y %Y" }, { "2024 20", "%Y %C" },
    { "SuNdAy September 01", "%a %b %d" },
    { "sun sep 1", "%A %B %e" }, { "Monday March 4", "%A %h %d" },
    { "Thuday", "%a" }, { "Septail", "%B" },
    { "12:34:56 AM", "%r" }, { "12:34:56 pM", "%r" },
    { "1:02:03 pm", "%r" }, { "13:00:00 AM", "%r" },
    { "00", "%I" }, { "23", "%H" }, { "24", "%H" },
    { "60", "%S" }, { "61", "%S" }, { "59tail", "%M" },
    { "1234", "%m%d" }, { " 1", "%e" }, { "01", "%d" },
    { "00", "%d" }, { "32", "%d" }, { "366", "%j" },
    { "367", "%j" }, { "7", "%u" }, { "7", "%w" },
    { "53 53 53 99 2024", "%U %V %W %g %G" },
    { "54", "%U" }, { "0", "%V" }, { "-123456789012345678901tail", "%s" },
    { "+1", "%s" }, { "  \tX\n%tail", "%nX %%%t" },
    { "02/29/24tail", "%D" }, { "02/29/24tail", "%x" },
    { "23:59tail", "%R" }, { "23:59:60tail", "%T" },
    { "23:59:60tail", "%X" }, { "Sun Sep  1 12:34:56 2024tail", "%c" },
    { "+0530tail", "%z" }, { "-1245tail", "%z" },
    { "+9999tail", "%z" }, { "+01", "%z" },
    { "UTCtail", "%Z" }, { "Unknown{tail", "%Z" },
    { "2024", "%EY" }, { "2024", "%Q" }, { "", "%" },
    { "tail", "" }, { "", "%Y" }, { "2024-13-05", "%F" },
};

int main(int argc, char **argv)
{
    static const char zone[] = "untouched";
    if (!setlocale(LC_ALL, "C") || setenv("TZ", "UTC0", 1)) return 1;
    tzset();
    if (argc == 2 && !strcmp(argv[1], "zone-guard")) {
        if (setenv("TZ", "STD0DST", 1)) return 8;
        tzset();
        long page = sysconf(_SC_PAGESIZE);
        if (page < 16) return 3;
        char *map = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || mprotect(map + page, (size_t)page, PROT_NONE)) return 4;
        char *input = map + page - sizeof "Unknown";
        memcpy(input, "Unknown", sizeof "Unknown");
        struct tm value = { .tm_isdst = -1 };
        errno = EDOM;
        char *end = strptime(input, "%Z", &value);
        if (end != input + 7 || value.tm_isdst != -1 || errno != EDOM) return 5;
        return munmap(map, (size_t)page * 2) != 0;
    }
    if (argc == 2 && !strcmp(argv[1], "zone-delimiters")) {
        static const char *inputs[] = { "STDtail", "DSTtail", "Unknown1{", "Unknown!{", "Unknown\t{", "Unknown\200{" };
        if (setenv("TZ", "STD0DST", 1)) return 8;
        tzset();
        for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
            struct tm value = { .tm_isdst = -1 };
            errno = EDOM;
            char *end = strptime(inputs[i], "%Z", &value);
            if (!end || errno != EDOM) return 9;
            printf("%zu end=%ld isdst=%d\n", i, (long)(end - inputs[i]), value.tm_isdst);
        }
        return 0;
    }
    if (argc != 1) return 6;
    if (setvbuf(stdout, 0, _IONBF, 0)) return 7;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct { unsigned long before; struct tm value; unsigned long after; } record;
        memset(&record, 0, sizeof record);
        record.before = 0x123456789abcdef0UL;
        record.after = 0xfedcba9876543210UL;
        record.value.tm_sec = 17; record.value.tm_min = 18;
        record.value.tm_hour = 19; record.value.tm_mday = 20;
        record.value.tm_mon = 3; record.value.tm_year = 123;
        record.value.tm_wday = 4; record.value.tm_yday = 99;
        record.value.tm_isdst = -1; record.value.tm_gmtoff = 6789;
        record.value.tm_zone = zone;
        errno = EDOM;
        char *end = strptime(cases[i].input, cases[i].format, &record.value);
        int error = errno;
        if (record.before != 0x123456789abcdef0UL || record.after != 0xfedcba9876543210UL) return 2;
        printf("%zu end=%ld tm=%d,%d,%d,%d,%d,%d,%d,%d,%d,%ld,%d errno=%d\n",
            i, end ? (long)(end - cases[i].input) : -1L,
            record.value.tm_sec, record.value.tm_min, record.value.tm_hour,
            record.value.tm_mday, record.value.tm_mon, record.value.tm_year,
            record.value.tm_wday, record.value.tm_yday, record.value.tm_isdst,
            record.value.tm_gmtoff, record.value.tm_zone == zone, error);
    }
    return 0;
}
