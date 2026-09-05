#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <locale.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "calendar:%d errno=%d\n", __LINE__, errno); exit(1); } } while (0)
/* Fixed records exclude pointers/padding and retain the full observable tm. */
static void record(time_t result, const struct tm *tm, int error) {
    int fields[] = {tm->tm_sec, tm->tm_min, tm->tm_hour, tm->tm_mday,
        tm->tm_mon, tm->tm_year, tm->tm_wday, tm->tm_yday, tm->tm_isdst, error};
    char name[32] = {0};
    if (tm->tm_zone) snprintf(name, sizeof name, "%s", tm->tm_zone);
    CHECK(fwrite(&result, sizeof result, 1, stdout) == 1);
    CHECK(fwrite(fields, sizeof fields, 1, stdout) == 1);
    CHECK(fwrite(&tm->tm_gmtoff, sizeof tm->tm_gmtoff, 1, stdout) == 1);
    CHECK(fwrite(name, sizeof name, 1, stdout) == 1);
}
static void formatted(const struct tm *tm, const char *format, size_t capacity, locale_t locale) {
    unsigned char bytes[192]; memset(bytes, 0xa5, sizeof bytes);
    errno = 0;
    size_t result = locale ? strftime_l((char *)bytes, capacity, format, tm, locale)
        : strftime((char *)bytes, capacity, format, tm);
    int error = errno;
    CHECK(fwrite(&result, sizeof result, 1, stdout) == 1);
    CHECK(fwrite(&error, sizeof error, 1, stdout) == 1);
    CHECK(fwrite(bytes, sizeof bytes, 1, stdout) == 1);
}
static void zone(const char *name) {
    CHECK(!setenv("TZ", name, 1));
    tzset();
    char names[32] = {0};
    snprintf(names, sizeof names, "%s|%s", tzname[0], tzname[1]);
    CHECK(fwrite(&timezone, sizeof timezone, 1, stdout) == 1);
    CHECK(fwrite(&daylight, sizeof daylight, 1, stdout) == 1);
    CHECK(fwrite(names, sizeof names, 1, stdout) == 1);
    static const time_t times[] = {-2208988800LL, -1, 0, 951782400, 1609459200,
        1615705199, 1615705200, 1636264799, 1636264800, 1672531200,
        1710053999, 1710054000, 1730613599, 1730613600, 2147483647,
        4102444800LL, 253402300799LL};
    for (size_t i=0; i<sizeof times/sizeof times[0]; i++) {
        struct tm tm = {0};
        CHECK(localtime_r(times+i, &tm) == &tm);
        record(times[i], &tm, 0);
        formatted(&tm, "%a|%A|%b|%B|%c|%C|%D|%F|%G|%g|%j|%r|%s|%u|%U|%V|%W|%x|%X|%z|%Z", 192, 0);
        for (int dst=-1; dst<=1; dst++) {
            struct tm inverse = tm; inverse.tm_isdst = dst;
            errno = 0;
            time_t result = mktime(&inverse);
            record(result, &inverse, errno);
        }
    }
    /* Spring gap, autumn fold, and normalization outside field ranges. */
    for (int day=0; day<2; day++) for (int dst=-1; dst<=1; dst++) {
        struct tm tm = {.tm_year=121, .tm_mon=day ? 10 : 2,
            .tm_mday=day ? 7 : 14, .tm_hour=day ? 1 : 2, .tm_min=30, .tm_isdst=dst};
        errno=0; time_t result=mktime(&tm); record(result, &tm, errno);
    }
    for (int dst=-1; dst<=1; dst++) {
        struct tm tm = {.tm_year=120, .tm_mon=-25, .tm_mday=70,
            .tm_hour=-49, .tm_min=121, .tm_sec=90, .tm_isdst=dst};
        errno=0; time_t result=mktime(&tm); record(result, &tm, errno);
    }
}
static void big32(unsigned char *p, uint32_t value) {
    p[0]=value>>24; p[1]=value>>16; p[2]=value>>8; p[3]=value;
}
static size_t header(unsigned char *p, unsigned count, unsigned types, unsigned names) {
    memset(p, 0, 44); memcpy(p, "TZif2", 5);
    big32(p+32, count); big32(p+36, types); big32(p+40, names);
    return 44;
}
static void timezone_file(const char *path) {
    unsigned char bytes[256] = {0};
    size_t n=header(bytes, 0, 1, 4);
    n+=6; memcpy(bytes+n, "UTC", 4); n+=4;
    n+=header(bytes+n, 4, 2, 8);
    const uint32_t transitions[] = {1615705200,1636264800,1647154800,1667714400};
    for (int i=0; i<4; i++) { big32(bytes+n, 0); big32(bytes+n+4, transitions[i]); n+=8; }
    bytes[n++]=1; bytes[n++]=0; bytes[n++]=1; bytes[n++]=0;
    big32(bytes+n, (uint32_t)-18000); n+=6;
    big32(bytes+n, (uint32_t)-14400); bytes[n+4]=1; bytes[n+5]=4; n+=6;
    memcpy(bytes+n, "STD\0DST\0", 8); n+=8;
    const char tail[]="\nSTD5DST,M3.2.0,M11.1.0\n";
    memcpy(bytes+n, tail, sizeof tail-1); n+=sizeof tail-1;
    FILE *file=fopen(path, "wb");
    CHECK(file && fwrite(bytes, 1, n, file)==n && !fclose(file));
    char setting[4099];
    CHECK(snprintf(setting, sizeof setting, ":%s", path)>0);
    zone(setting);
    CHECK(!unlink(path));
}
#ifdef CRABC_OWNED_CALENDAR
static void malformed_timezone_file(const char *path) {
    unsigned char bytes[44]; header(bytes, UINT_MAX, UINT_MAX, UINT_MAX);
    FILE *file=fopen(path, "wb");
    CHECK(file && fwrite(bytes, 1, sizeof bytes, file)==sizeof bytes && !fclose(file));
    CHECK(!setenv("TZ", "UTC0", 1)); tzset();
    CHECK(!setenv("TZ", path, 1)); tzset();
    time_t epoch=0; struct tm tm;
    CHECK(localtime_r(&epoch, &tm) && tm.tm_gmtoff==0 && !strcmp(tm.tm_zone,"UTC"));
    CHECK(!unlink(path));
}
#endif
static void *calendar_worker(void *unused) {
    (void)unused;
    for (time_t seconds=0; seconds<1000; seconds++) {
        struct tm local, utc;
        CHECK(localtime_r(&seconds, &local) && gmtime_r(&seconds, &utc));
        CHECK(local.tm_sec == utc.tm_sec && local.tm_min == utc.tm_min &&
            local.tm_hour == utc.tm_hour && local.tm_mday == utc.tm_mday &&
            local.tm_mon == utc.tm_mon && local.tm_year == utc.tm_year);
    }
    return NULL;
}
int main(int argc, char **argv) {
    CHECK(argc == 2); /* Private TZif pathname, never a shared fixture. */
    static const char *zones[] = {"", "UTC0", "GMT-3", "EST5EDT,M3.2.0,M11.1.0",
        "AEST-10AEDT-11,M10.1.0,M4.1.0/3", "NST3:30NDT2:30,M3.2.0,M11.1.0",
        "<+0545>-5:45", "AAA0BBB,J60/0,J300/25", "AAA0BBB,59/-2,300/26",
        "<LMT>-5:41:16", "<LongStandardName>5<LongDaylightName>,M3.2.0,M11.1.0", "EST5EDT",
        "America/New_York", "Europe/Berlin", "Australia/Lord_Howe", ":/etc/localtime"};
    for (size_t i=0; i<sizeof zones/sizeof zones[0]; i++) zone(zones[i]);
    timezone_file(argv[1]);
    char long_setting[4200]; memset(long_setting, 'X', sizeof long_setting-1);
    long_setting[sizeof long_setting-1]=0;
    zone(long_setting);
    CHECK(!setenv("TZ", "UTC0", 1)); tzset();
    locale_t c = newlocale(LC_ALL_MASK, "C", 0);
    locale_t utf8 = newlocale(LC_ALL_MASK, "C.UTF-8", 0);
    CHECK(c && utf8);
    const char *formats[] = {"%Y|%C|%G|%F|%y|%g", "%+6Y|%6Y|%_Y|%-Y|%06Y|%+3C|%+12F",
        "%Ec|%Od|%EY|%OH|%Om|%OV|%%|%n|%t", "abc%Qend", "end%", "%Z|%z"};
    const int years[] = {-2001,-1901,-1900,-1899,-1,0,100,121,8099,8100,INT_MAX};
    for (size_t y=0; y<sizeof years/sizeof years[0]; y++) {
        struct tm tm = {.tm_year=years[y], .tm_mon=0, .tm_mday=1};
        timegm(&tm);
        for (size_t f=0; f<sizeof formats/sizeof formats[0]; f++)
            for (size_t n=0; n<=64; n+=8) {
                formatted(&tm, formats[f], n, c);
                formatted(&tm, formats[f], n, utf8);
            }
    }
    time_t extremes[] = {INT64_MIN, INT64_MAX};
    for (int i=0; i<2; i++) {
        struct tm tm = {0}; errno=0;
        CHECK(!localtime_r(extremes+i, &tm) && errno==EOVERFLOW);
        record(extremes[i], &tm, errno);
    }
    struct tm overflow = {.tm_year=INT_MAX, .tm_mon=INT_MAX, .tm_mday=1};
    struct tm before = overflow;
    errno=0;
    CHECK(mktime(&overflow)==-1 && errno==EOVERFLOW && !memcmp(&overflow, &before, sizeof overflow));
    time_t epoch = 0;
    CHECK(!strcmp(ctime(&epoch), "Thu Jan  1 00:00:00 1970\n"));
    char text[26]; struct tm tm;
    CHECK(gmtime_r(&epoch, &tm) && !strcmp(asctime_r(&tm, text), "Thu Jan  1 00:00:00 1970\n"));
    CHECK(gmtime(&epoch) && localtime(&epoch) && ctime_r(&epoch, text));
    pthread_t threads[2];
    CHECK(!pthread_create(threads, NULL, calendar_worker, NULL));
    CHECK(!pthread_create(threads+1, NULL, calendar_worker, NULL));
    calendar_worker(NULL);
    CHECK(!pthread_join(threads[0], NULL) && !pthread_join(threads[1], NULL));
#ifdef CRABC_OWNED_CALENDAR
    malformed_timezone_file(argv[1]);
#endif
    freelocale(c); freelocale(utf8);
    return 0;
}
