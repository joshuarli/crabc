#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <fenv.h>
#include <limits.h>

/* Binary records intentionally bypass printf: compare return, errno, fenv,
 * rounding-mode preservation, and every retained byte against pinned musl.
 * Caller-side float arithmetic completes before clearing exception state. */
static void record(const char *format, ...)
{
    char buffer[20032];
    memset(buffer, 0x55, sizeof buffer);
    va_list args;
    va_start(args, format);
    feclearexcept(FE_ALL_EXCEPT);
    feraiseexcept(FE_DIVBYZERO);
    errno = EDOM;
    int count = vsnprintf(buffer, sizeof buffer, format, args);
    int state[] = {count, errno, fetestexcept(FE_ALL_EXCEPT), fegetround()};
    va_end(args);
    if (write(1, state, sizeof state) != sizeof state) _Exit(90);
    size_t bytes = count < 0 ? 1 : (size_t)count + 1;
    if (bytes > sizeof buffer) bytes = sizeof buffer;
    if (write(1, buffer, bytes) != (ssize_t)bytes) _Exit(91);
}

static int destinations(const char *path)
{
    char expected[512], actual[512], *allocated = NULL;
    const char *format = "%3$+#28.18Lg|%2$.17e|%1$La";
    long double a = 0x1.0000000000000002p0L, b = -0x1.fffffffffffffffep120L;
    double d = 0x1.fffffffffffffp-1022;
    int length = snprintf(expected, sizeof expected, format, a, d, b);
    if (length < 0 || asprintf(&allocated, format, a, d, b) != length) return 1;
    if (memcmp(expected, allocated, length + 1)) return 2;
    free(allocated);
    FILE *stream = fopen(path, "w+");
    if (stream) unlink(path);
    if (!stream || fprintf(stream, format, a, d, b) != length) return 3;
    if (fflush(stream) || fseek(stream, 0, SEEK_SET)) return 4;
    if (fread(actual, 1, length, stream) != (size_t)length || memcmp(expected, actual, length)) return 5;
    if (fclose(stream)) return 6;
    int descriptors[2];
    if (pipe(descriptors)) return 7;
    if (dprintf(descriptors[1], format, a, d, b) != length) return 8;
    close(descriptors[1]);
    if (read(descriptors[0], actual, sizeof actual) != length || memcmp(expected, actual, length)) return 9;
    close(descriptors[0]);
    errno = 0;
    if (dprintf(-1, "%Lf", a) != -1 || errno != EBADF) return 10;
    int stored = -1;
    char small[3];
    if (snprintf(small, sizeof small, "%.5f%n", 1.25, &stored) != 7 || stored != 7 || strcmp(small, "1.")) return 11;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 79;
    union { uint64_t bits; double value; } signaling = {UINT64_C(0x7ff0000000000001)};
    long double signaling_extended;
    const unsigned char signaling_bytes[sizeof(long double)] = {1, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x7f};
    memcpy(&signaling_extended, signaling_bytes, sizeof signaling_extended);
    const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    const double doubles[] = {0., -0., 0.5, -0.5, 1.25, -1.25, 9.999999999999998,
        0.1, 0x1p-1074, 0x1.fffffffffffffp-1023, DBL_MIN, DBL_MAX,
        INFINITY, -INFINITY, NAN, -NAN};
    const long double extended[] = {0.L, -0.L, 0.5L, -0.5L, 1.25L, -1.25L,
        0x1.0000000000000002p0L, 0x1.fffffffffffffffep63L,
        0x1p-16445L, LDBL_MIN, LDBL_MAX, INFINITY, -INFINITY, NAN, -NAN};
    const char *df[] = {"%f", "%+.0f", "%#.0f", "%020.5f", "%- 25.8e", "%#.17g",
        "%G", "%.0g", "%.22E", "%a", "%+#25.0A", "%.13a", "%.200f"};
    const char *lf[] = {"%Lf", "%+.0Lf", "%#.0Lf", "%020.5Lf", "%- 25.8Le", "%#.21Lg",
        "%LG", "%.0Lg", "%.30LE", "%La", "%+#25.0LA", "%.16La", "%.200Lf"};
    for (size_t m = 0; m < sizeof modes / sizeof *modes; ++m) {
        if (fesetround(modes[m])) return 80;
        for (size_t i = 0; i < sizeof doubles / sizeof *doubles; ++i)
            for (size_t j = 0; j < sizeof df / sizeof *df; ++j) record(df[j], doubles[i]);
        for (size_t i = 0; i < sizeof extended / sizeof *extended; ++i)
            for (size_t j = 0; j < sizeof lf / sizeof *lf; ++j) record(lf[j], extended[i]);
        record("%f/%g/%a", (float)0.1f, (float)FLT_MIN, (float)FLT_MAX);
        record("%3$*1$.*2$Lf/%4$.17g", -32, 20, extended[6], doubles[7]);
        /* Long double is stack-only even while GP/SSE registers remain;
         * then both register banks overflow before another aligned slot. */
        record("%Lf/%d/%.17g/%Lf/%d/%d/%d/%d/%d/%d/%d/%g/%g/%g/%g/%g/%g/%g/%g/%Lf",
            extended[6], 1, 0.1, extended[7], 2, 3, 4, 5, 6, 7, 8,
            1., 2., 3., 4., 5., 6., 7., 8., extended[8]);
        record("%9$Lg/%8$Lg/%7$Lg/%6$Lg/%5$Lg/%4$Lg/%3$Lg/%2$Lg/%1$Lg",
            1.L, 2.L, 3.L, 4.L, 5.L, 6.L, 7.L, 8.L, 9.L);
        record("%.16445Lf", extended[8]);
        record("%.*f", INT_MAX, 1.0);
        record("%f/%e/%g/%a", signaling.value, signaling.value, signaling.value, signaling.value);
        record("%Lf/%Le/%Lg/%La", signaling_extended, signaling_extended, signaling_extended, signaling_extended);
        record("%+.0f/%+.0f/%+.0f/%+.0f", 2.5, 3.5, -2.5, -3.5);
        record("%1$+.2Lf/%1$#.20Lg/%1$La", 1.005L);
        record("%+-020.3f/% 020.3f/%#20.0g", -0.0, 12.5, 1.0);
        /* Deterministic exponent/mantissa boundaries, not a host PRNG. */
        for (unsigned exponent = 1; exponent < 2047; exponent += 31) {
            union { uint64_t bits; double value; } edge = {
                ((uint64_t)exponent << 52) | UINT64_C(0x0008000000000001)
            };
            record("%.17g/%.6e/%.9f", edge.value, -edge.value, edge.value);
        }
    }
    if (fesetround(FE_TONEAREST)) return 81;
    return destinations(argv[1]);
}
