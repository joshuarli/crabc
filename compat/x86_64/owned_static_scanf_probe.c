#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fenv.h>
#include <unistd.h>
#include <sys/resource.h>

/* Fixed records: six int32 fields followed by 64 initialized result bytes.
 * Compare actual C varargs, assignment count, errno, fenv, and stream's next
 * byte/EOF/error state. argv[1] is private scratch for this process. */
static const char *path;
static int stream_mode;
static int forwarded_stdin(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vscanf(format, args);
    va_end(args);
    return result;
}
static void check(const char *input, const char *format, unsigned char data[64], ...)
{
    FILE *stream = NULL;
    if (stream_mode) {
        stream = fopen(path, "w+");
        if (!stream || fwrite(input, 1, strlen(input), stream) != strlen(input)
            || fseek(stream, 0, SEEK_SET)) _Exit(90);
    }
    va_list args;
    va_start(args, data);
    feclearexcept(FE_ALL_EXCEPT);
    errno = EDOM;
    int result = stream ? vfscanf(stream, format, args) : vsscanf(input, format, args);
    int record[] = {result, errno, fetestexcept(FE_ALL_EXCEPT), 0, 0, 0};
    va_end(args);
    if (stream) {
        record[4] = !!feof(stream);
        record[5] = !!ferror(stream);
        record[3] = fgetc(stream);
        if (fclose(stream)) _Exit(91);
    }
    if (write(1, record, sizeof record) != sizeof record || write(1, data, 64) != 64) _Exit(92);
}

static int allocations(void)
{
    char *a = NULL, *b = NULL, *c = NULL;
    int consumed = -1;
    if (sscanf("abcdefgh:xyz 012345", "%m[^:]:%ms %3mc%n", &a, &b, &c, &consumed) != 3
        || strcmp(a, "abcdefgh") || strcmp(b, "xyz") || memcmp(c, "012", 3) || consumed != 16) return 1;
    free(a); free(b); free(c);
    a = (char *)(uintptr_t)1;
    if (sscanf("xy", "%3mc", &a) != 0 || a != (char *)(uintptr_t)1) return 2;
    char large[8194];
    memset(large, 'a', sizeof large - 1); large[sizeof large - 1] = 0;
    if (sscanf(large, "%ms%n", &a, &consumed) != 1 || consumed != sizeof large - 1
        || strcmp(a, large)) return 3;
    free(a);
    a = NULL;
    if (sscanf("word ?", "%ms %d", &a, &consumed) != 1 || strcmp(a, "word")) return 4;
    free(a);
    FILE *stream = fopen(path, "w+");
    if (!stream) return 5;
    if (fputs("17 2.5 tail!", stream) < 0 || fseek(stream, 0, SEEK_SET)) return 6;
    int integer = 0; double real = 0;
    flockfile(stream);
    if (fscanf(stream, "%d %lf %m[a-z]", &integer, &real, &a) != 3
        || integer != 17 || real != 2.5 || strcmp(a, "tail") || getc_unlocked(stream) != '!') return 7;
    funlockfile(stream);
    free(a);
    int fd = fileno(stream);
    if (fseek(stream, 0, SEEK_END) || close(fd)) return 8;
    errno = 0;
    if (fscanf(stream, "%d", &integer) != EOF || errno != EBADF || !ferror(stream)) return 9;
    fclose(stream);
    stream = fopen(path, "w+");
    const unsigned char binary[] = {'a', 0, 'b', '!'};
    unsigned char copied[4] = {0};
    if (!stream || fwrite(binary, 1, 4, stream) != 4 || fseek(stream, 0, SEEK_SET)) return 10;
    if (fscanf(stream, "%3c%n", copied, &consumed) != 1 || consumed != 3
        || memcmp(copied, binary, 3) || fgetc(stream) != '!') return 11;
    fclose(stream);
    stream = fopen(path, "w");
    errno = EAGAIN;
    if (!stream || fscanf(stream, "") != EOF || errno != EAGAIN || !ferror(stream)) return 12;
    fclose(stream);
    /* Force the original %mc up-front allocation to fail; preserve both the
     * old destination and the caller's original resource limit afterward. */
    struct rlimit original, constrained;
    if (getrlimit(RLIMIT_AS, &original)) return 13;
    constrained = original;
    if (constrained.rlim_cur > 256UL*1024*1024) constrained.rlim_cur = 256UL*1024*1024;
    if (setrlimit(RLIMIT_AS, &constrained)) return 14;
    a = (char *)(uintptr_t)1;
    errno = 0;
    int allocation_result = sscanf("x", "%2147483647mc", &a);
    int allocation_errno = errno;
    if (setrlimit(RLIMIT_AS, &original)) return 15;
    if (allocation_result != EOF || allocation_errno != ENOMEM || a != (char *)(uintptr_t)1) return 16;
    int saved_stdin = dup(0), descriptors[2], first = 0, second = 0;
    if (saved_stdin < 0 || pipe(descriptors) || write(descriptors[1], "19 21", 5) != 5) return 17;
    close(descriptors[1]);
    if (dup2(descriptors[0], 0) != 0) return 18;
    close(descriptors[0]);
    if (scanf("%d", &first) != 1 || forwarded_stdin("%d", &second) != 1
        || first != 19 || second != 21 || !feof(stdin)) return 19;
    if (dup2(saved_stdin, 0) != 0) return 20;
    close(saved_stdin);
    clearerr(stdin);
#ifdef CRABC_OWNED_SCANF
    /* Owned wide destinations share the source byte parser and allocation. */
    int wide_storage[8] = {0};
    errno = 0;
    if (sscanf("wide", "%ls", wide_storage) != 1 || errno || wide_storage[0]!='w' || wide_storage[4]) return 21;
    int *allocated_wide = NULL;
    errno = 0;
    if (sscanf("wide", "%mls", &allocated_wide) != 1 || errno || !allocated_wide || allocated_wide[0]!='w' || allocated_wide[4]) return 22;
    free(allocated_wide);
#endif
    unlink(path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 80;
    path = argv[1];
    union { unsigned char bytes[64]; long double alignment; } data;
    const char *integers[] = {"", " ", "+", "-", "0", "0129!", "0x", "0xq!", "0x123!",
        "-19!", "18446744073709551616!", "-18446744073709551616!", "xyz", "  42!"};
    const char *integer_formats[] = {"%lli%n", "%llu%n", "%llx%n", "%3lli%n", "%*i%n"};
    const char *floats[] = {"", "+", "-0", "0.1!", "1e+", "1e+x", "0x", "0x.p1",
        "0x1.0000000000000001p0!", "infinite", "infinity!", "nan(payload)!", "nan(bad!",
        "1e99999!", "-1e-99999!", "1.17549435082228750796873653722224568e-38!",
        "4.94065645841246544176568792868221372e-324!", "3.36210314311209350626267781732175260e-4932!"};
    const char *float_formats[] = {"%f%n", "%lf%n", "%Lf%n", "%4lf%n", "%*f%n"};
    const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    for (stream_mode = 0; stream_mode < 2; ++stream_mode) {
        for (size_t i=0; i<sizeof integers/sizeof *integers; ++i)
            for (size_t j=0; j<sizeof integer_formats/sizeof *integer_formats; ++j) {
                memset(data.bytes, 0, 64);
                if (j==4) check(integers[i], integer_formats[j], data.bytes, data.bytes+32);
                else check(integers[i], integer_formats[j], data.bytes, data.bytes, data.bytes+32);
            }
        for (size_t m=0; m<4; ++m) {
            if (fesetround(modes[m])) return 81;
            for (size_t i=0; i<sizeof floats/sizeof *floats; ++i)
                for (size_t j=0; j<sizeof float_formats/sizeof *float_formats; ++j) {
                    memset(data.bytes, 0, 64);
                    if (j==4) check(floats[i], float_formats[j], data.bytes, data.bytes+32);
                    else check(floats[i], float_formats[j], data.bytes, data.bytes, data.bytes+32);
                }
        }
        if (fesetround(FE_TONEAREST)) return 82;
        const char *text[] = {"", "a", "abc!", "  alpha beta", "]-xyz!", "12-34!"};
        const char *formats[] = {"%3c%n", "%3s%n", "%[a-z]%n", "%[^!]%n", "%[]-]%n", "%*3[a-z]%n"};
        for (size_t i=0; i<6; ++i) for (size_t j=0; j<6; ++j) {
            memset(data.bytes, 0, 64);
            if (j==5) check(text[i], formats[j], data.bytes, data.bytes+32);
            else check(text[i], formats[j], data.bytes, data.bytes, data.bytes+32);
        }
        memset(data.bytes, 0, 64);
        check("11 22!", "%2$d %1$d%3$n", data.bytes, data.bytes, data.bytes+8, data.bytes+32);
        memset(data.bytes, 0, 64);
        check("255 65535 -7 0x123!", "%hhd %hd %jd %p%n", data.bytes,
            data.bytes, data.bytes+2, data.bytes+8, data.bytes+16, data.bytes+32);
        memset(data.bytes, 0, 64);
        check(" \t% xyz!", " %% %*3c%hhn%hn%ln%lln%zn%tn", data.bytes,
            data.bytes, data.bytes+2, data.bytes+8, data.bytes+16, data.bytes+24, data.bytes+32);
        memset(data.bytes, 0, 64);
        check("abc!", "%*nabc%n", data.bytes, data.bytes+32);
    }
    return allocations();
}
