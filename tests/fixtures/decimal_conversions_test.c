#define _GNU_SOURCE 1

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_ecvt(double value, int ndigit, const char *want,
    int want_decpt, int want_sign)
{
    int decpt = -99;
    int sign = -99;
    char *result = ecvt(value, ndigit, &decpt, &sign);
    return strcmp(result, want) != 0 || decpt != want_decpt || sign != want_sign;
}

static int check_fcvt(double value, int ndigit, const char *want,
    int want_decpt, int want_sign)
{
    int decpt = -99;
    int sign = -99;
    char *result = fcvt(value, ndigit, &decpt, &sign);
    return strcmp(result, want) != 0 || decpt != want_decpt || sign != want_sign;
}

int main(void)
{
    if (check_ecvt(123.456, 6, "123456", 3, 0)) return 1;
    if (check_ecvt(-0.0123456, 5, "12346", -1, 1)) return 2;
    if (check_ecvt(9.999, 3, "100", 2, 0)) return 3;
    if (check_ecvt(-0.0, 4, "0000", 1, 1)) return 4;

    if (check_fcvt(123.456, 2, "12346", 3, 0)) return 5;
    if (check_fcvt(0.001234, 5, "123", -2, 0)) return 6;
    if (check_fcvt(-0.0004, 2, "000", 1, 1)) return 7;

    int ecvt_decpt = 0;
    int ecvt_sign = 0;
    char *ecvt_result = ecvt(12.5, 5, &ecvt_decpt, &ecvt_sign);
    int fcvt_decpt = 0;
    int fcvt_sign = 0;
    char *fcvt_result = fcvt(12.5, 2, &fcvt_decpt, &fcvt_sign);
    if (ecvt_result != fcvt_result) return 8;
    if (strcmp(ecvt_result, "1250") != 0) return 9;

    int decpt = -99;
    int sign = -99;
    if (strcmp(ecvt(NAN, 10, &decpt, &sign), "nan") != 0
        || decpt != 0 || sign != 0) return 10;
    if (strcmp(ecvt(-INFINITY, 10, &decpt, &sign), "inf") != 0
        || decpt != 0 || sign != 1) return 11;

    char gcvt_buf[64];
    if (gcvt(123.456, 6, gcvt_buf) != gcvt_buf
        || strcmp(gcvt_buf, "123.456") != 0) return 12;
    if (strcmp(gcvt(0.0000123456, 6, gcvt_buf), "1.23456e-05") != 0) return 13;
    if (strcmp(gcvt(INFINITY, 6, gcvt_buf), "inf") != 0) return 14;
    char long_gcvt_buf[256];
    if (strcmp(gcvt(0.1, 100, long_gcvt_buf),
        "0.1000000000000000055511151231257827021181583404541015625") != 0) return 15;

    // Musl bounds ecvt to 15 significant digits and fcvt to 1400 fractional
    // digits (with only the representable significant result retained).
    if (strcmp(ecvt(1.2345678901234567, 10000, &decpt, &sign),
        "123456789012346") != 0 || decpt != 1 || sign != 0) return 16;
    if (strcmp(fcvt(1.25, -1, &decpt, &sign), "125000000000000") != 0
        || decpt != 1 || sign != 0) return 17;
    if (strcmp(fcvt(0.0, 10000, &decpt, &sign), "000000000000000") != 0
        || decpt != 1 || sign != 0) return 18;

    puts("c-abi decimal conversions ok");
    return 0;
}
