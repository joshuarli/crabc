/*
 * Component-only real-zone checks for the installed calendar receipt.
 *
 * `owned_calendar_probe.c` deliberately remains the historical broad
 * differential stream.  Its named-zone records establish neither that the
 * named files were found nor that their transitions were applied: both
 * providers can fall back to UTC.  This small companion has fixed UTC
 * instants and checks the resulting civil time, UTC offset, DST flag, and
 * abbreviation.  The receipt supplies its named TZif files in each chroot.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct expectation {
    const char *label;
    const char *zone;
    time_t instant;
    int year;
    int month;
    int day;
    int hour;
    int minute;
    long offset;
    int isdst;
    const char *abbreviation;
};

static int matches(const struct expectation *expected) {
    struct tm value;
    char abbreviation[16];

    if (setenv("TZ", expected->zone, 1) != 0) return 0;
    tzset();
    if (localtime_r(&expected->instant, &value) == NULL) return 0;
    if (strftime(abbreviation, sizeof abbreviation, "%Z", &value) == 0) return 0;
    return value.tm_year + 1900 == expected->year &&
           value.tm_mon + 1 == expected->month &&
           value.tm_mday == expected->day &&
           value.tm_hour == expected->hour &&
           value.tm_min == expected->minute &&
           value.tm_gmtoff == expected->offset &&
           value.tm_isdst == expected->isdst &&
           strcmp(abbreviation, expected->abbreviation) == 0;
}

static int failed(const char *label) {
    fprintf(stderr, "owned-calendar-real-zones: fixture assertion failed: %s\n", label);
    return 1;
}

static const struct expectation expectations[] = {
    {"New_York-winter", "America/New_York", (time_t)1609459200,
     2020, 12, 31, 19, 0, -18000, 0, "EST"},
    {"New_York-summer", "America/New_York", (time_t)1625097600,
     2021, 6, 30, 20, 0, -14400, 1, "EDT"},
    {"Berlin-winter", "Europe/Berlin", (time_t)1609459200,
     2021, 1, 1, 1, 0, 3600, 0, "CET"},
    {"Berlin-summer", "Europe/Berlin", (time_t)1625097600,
     2021, 7, 1, 2, 0, 7200, 1, "CEST"},
    {"Lord_Howe-January", "Australia/Lord_Howe", (time_t)1609459200,
     2021, 1, 1, 11, 0, 39600, 1, "+11"},
    {"Lord_Howe-July", "Australia/Lord_Howe", (time_t)1625097600,
     2021, 7, 1, 10, 30, 37800, 0, "+1030"},
    {"localtime-winter", ":/etc/localtime", (time_t)1609459200,
     2020, 12, 31, 19, 0, -18000, 0, "EST"},
    {"localtime-summer", ":/etc/localtime", (time_t)1625097600,
     2021, 6, 30, 20, 0, -14400, 1, "EDT"},
};

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--missing-lord-howe") == 0) {
        if (!matches(&expectations[4])) return failed(expectations[4].label);
        fputs("owned-calendar-real-zones: missing fixture unexpectedly supplied\n", stderr);
        return 1;
    }
    if (argc != 1) return 2;
    for (size_t index = 0; index < sizeof expectations / sizeof expectations[0]; ++index) {
        if (!matches(&expectations[index])) return failed(expectations[index].label);
    }
    fputs("owned-calendar-real-zones: New_York Berlin Lord_Howe localtime\n", stdout);
    return 0;
}
