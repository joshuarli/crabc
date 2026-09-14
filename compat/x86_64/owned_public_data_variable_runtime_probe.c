/* Narrow installed-product signgam and POSIX-TZ global contract; it intentionally
 * is not math-family or timezone-family evidence. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern int signgam;
extern int __signgam;
extern long timezone;
extern long __timezone;
extern int daylight;
extern int __daylight;
extern char *tzname[2];
extern char *__tzname[2];

static int signgam_probe(void) {
    int explicit_sign = 0;

    if (&signgam != &__signgam) return 10;
    signgam = -73;
    if (!isfinite(lgamma(0.5)) || signgam != 1) return 11;
    signgam = 73;
    if (!isfinite(lgamma_r(-0.5, &explicit_sign))) return 12;
    if (explicit_sign != -1 || signgam != 73) return 13;
    return write(1, "math-sign-global-ok\n", 20) == 20 ? 0 : 14;
}

static int timezone_probe(void) {
    if (&timezone != &__timezone || &daylight != &__daylight ||
        tzname != __tzname) return 20;
    if (setenv("TZ", "UTC0", 1)) return 21;
    tzset();
    if (timezone != 0 || daylight != 0 || !tzname[0] || !tzname[1] ||
        strcmp(tzname[0], "UTC") || strcmp(tzname[1], "")) return 21;
    if (setenv("TZ", "EST5EDT,M3.2.0,M11.1.0", 1)) return 22;
    tzset();
    if (timezone != 18000 || daylight != 1 || !tzname[0] || !tzname[1] ||
        strcmp(tzname[0], "EST") || strcmp(tzname[1], "EDT")) return 22;
    return write(1, "timezone-globals-ok\n", 20) == 20 ? 0 : 23;
}

int main(int argc, char **argv) {
    if (argc == 1) return signgam_probe();
    if (argc == 2 && !strcmp(argv[1], "timezone")) return timezone_probe();
    return 24;
}
