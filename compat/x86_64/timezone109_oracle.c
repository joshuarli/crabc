#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
static void record(long long result, struct tm *value) {
    printf("%lld %d %d %d %d %d %d %d %d %d %ld %s %d\n", result,
        value->tm_year, value->tm_mon, value->tm_mday, value->tm_hour,
        value->tm_min, value->tm_sec, value->tm_wday, value->tm_yday,
        value->tm_isdst, value->tm_gmtoff, value->tm_zone, errno);
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    if (!strcmp(argv[1],"-")) { if (unsetenv("TZ")) return 2; }
    else if (setenv("TZ",argv[1],1)) return 2;
    tzset();
    errno=47;
    if (argv[2][0]=='l') {
        time_t input=strtoll(argv[3], 0, 10);
        struct tm value={0};
        if (!localtime_r(&input,&value)) return 3;
        record(input,&value);
    } else {
        if (argc!=10) return 4;
        struct tm value={.tm_year=atoi(argv[3]),.tm_mon=atoi(argv[4]),
            .tm_mday=atoi(argv[5]),.tm_hour=atoi(argv[6]),.tm_min=atoi(argv[7]),
            .tm_sec=atoi(argv[8]),.tm_isdst=atoi(argv[9])};
        time_t result=mktime(&value);
        record(result,&value);
    }
    return 0;
}
