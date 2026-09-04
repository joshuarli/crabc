#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* Binary count/errno/payload records avoid using printf to encode its own
 * differential evidence. All payloads fit this fixed probe buffer. */
static int matrix_case(const char *format, ...)
{
    char bytes[512];
    va_list args;
    va_start(args, format);
    errno = ENOENT;
    int count = vsnprintf(bytes, sizeof bytes, format, args);
    int error = errno;
    va_end(args);
    if (count >= (int)sizeof bytes) return 1;
    if (write(STDOUT_FILENO, &count, sizeof count) != sizeof count
        || write(STDOUT_FILENO, &error, sizeof error) != sizeof error) return 1;
    if (count > 0 && write(STDOUT_FILENO, bytes, (size_t)count) != count) return 1;
    return 0;
}

static int differential_matrix(void)
{
    const char *signed_formats[] = { "%d", "%+08d", "% 9.5d", "%-.0d", "%09.0d", "%*.*d" };
    const int signed_values[] = { INT_MIN, -127, 0, 42, INT_MAX };
    for (size_t f = 0; f < sizeof signed_formats / sizeof *signed_formats; ++f)
        for (size_t v = 0; v < sizeof signed_values / sizeof *signed_values; ++v) {
            int result = f == 5 ? matrix_case(signed_formats[f], -12, 7, signed_values[v])
                                : matrix_case(signed_formats[f], signed_values[v]);
            if (result) return 1;
        }
    const char *unsigned_formats[] = { "%u", "%#o", "%#.0o", "%#010x", "%#10.8X", "%hhu/%hu" };
    const unsigned values[] = { 0, 1, 255, 65537, UINT_MAX };
    for (size_t f = 0; f < sizeof unsigned_formats / sizeof *unsigned_formats; ++f)
        for (size_t v = 0; v < sizeof values / sizeof *values; ++v)
            if (f == 5 ? matrix_case(unsigned_formats[f], (int)values[v], (int)values[v])
                       : matrix_case(unsigned_formats[f], values[v])) return 1;
    if (matrix_case("%lld/%llu/%jd/%ju/%zd/%zu/%td/%tu", LLONG_MIN, ULLONG_MAX,
            (intmax_t)INT64_MIN, (uintmax_t)UINT64_MAX, (ssize_t)-9, (size_t)9,
            (ptrdiff_t)-10, (size_t)10)
        || matrix_case("%2$*1$.*3$s/%2$s/%4$d", -10, "abcdef", 3, 19)
        || matrix_case("%1$hhd/%1$d", 200)
        || matrix_case("%p/%.0p/%020p/%20.3p", (void *)0, (void *)0,
            (void *)(uintptr_t)0x1234, (void *)(uintptr_t)0x1234)
        || matrix_case("%c/%5c/%.0s/%10.3s/%s", 0, 'Q', "abc", "abcdef", (char *)0)
        || matrix_case("%m/%20.7m/%*m/%d", -30, 42)
        || matrix_case("%a/%A/%#.0a/%020.5a/%-20.2a", 0.0, -0.0, 1.5, 3.141592653589793, -0x1.fp-8)
        || matrix_case("%a/%a/%+A", 0x1p-1074, __builtin_inf(), __builtin_nan(""))
        || matrix_case("%2147483648d", 1)
        || matrix_case("%2$d", 1, 2)
        || matrix_case("%Q")) return 1;
    return 0;
}

static int forwarded(char *buffer, size_t capacity, FILE *stream, int fd,
                     char **allocated, const char *format, ...)
{
    va_list arguments, copy;
    va_start(arguments, format);
    va_copy(copy, arguments);
    int count = vsnprintf(buffer, capacity, format, copy);
    va_end(copy);
    va_copy(copy, arguments);
    int stream_count = vfprintf(stream, format, copy);
    va_end(copy);
    va_copy(copy, arguments);
    int fd_count = vdprintf(fd, format, copy);
    va_end(copy);
    int allocated_count = vasprintf(allocated, format, arguments);
    va_end(arguments);
    if (count < 0 || stream_count != count || fd_count != count || allocated_count != count) return -1;
    return count;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    if (!strcmp(argv[1], "--matrix")) return differential_matrix();
    char buffer[512];
    int stored = -1;
    const char *format = "%2$*1$.*3$s/%4$#x/%5$hhd/%6$zu/%7$p/%8$n%9$a";
    const char expected[] = "  abc/0x2a/-1/99/0x1234/0x1.8p+0";
    int count = snprintf(buffer, sizeof buffer, format,
        5, "abcdef", 3, 42U, 255, (size_t)99, (void *)(uintptr_t)0x1234, &stored, 1.5);
    if (count != (int)strlen(expected) || strcmp(buffer, expected)
        || stored != (int)strlen("  abc/0x2a/-1/99/0x1234/")) {
        fprintf(stderr, "positional count=%d stored=%d bytes=[%s]\n", count, stored, buffer);
        return 2;
    }
    char small[5];
    if (snprintf(small, sizeof small, "%2$s/%1$d", 12, "abcdef") != 9
        || strcmp(small, "abcd") || snprintf(NULL, 0, "%p", (void *)0) != 1
        || snprintf(NULL, 0, "%.0p", (void *)0) != 16) return 3;
    if (snprintf(small, sizeof small, "abcdef%n", &stored) != 6 || stored != 6 || strcmp(small, "abcd")) return 25;
    signed char hh = -1;
    short h = -1;
    long l = -1;
    long long ll = -1;
    intmax_t j = -1;
    ptrdiff_t t = -1;
    ssize_t z = -1;
    if (snprintf(buffer, sizeof buffer, "a%hhn%hn%ln%lln%jn%tn%zn", &hh, &h, &l, &ll, &j, &t, &z) != 1
        || hh != 1 || h != 1 || l != 1 || ll != 1 || j != 1 || t != 1 || z != 1) return 4;
    errno = ENOENT;
    if (snprintf(buffer, sizeof buffer, "%20.7m/%d/%'u", 42, 1234567U) != 31
        || strcmp(buffer, "             No such/42/1234567")) return 5;
    FILE *stream = fopen(argv[1], "w+");
    if (!stream || setvbuf(stream, NULL, _IONBF, 0)) return 6;
    int fd = open(argv[1], O_WRONLY | O_APPEND);
    if (fd < 0) return 7;
    char *allocated = NULL;
    errno = ENOENT;
    const char shared[] = "%3$#x/%2$.*1$s/%4$p/%5$a/%m\n";
    count = forwarded(buffer, sizeof buffer, stream, fd, &allocated,
        shared, 3, "abcdef", 42U, (void *)(uintptr_t)0x1234, 1.5);
    if (count < 0 || !allocated || strcmp(buffer, allocated) || fflush(stream)) return 8;
    free(allocated);
    if (lseek(fd, 0, SEEK_CUR) != count * 2 || close(fd) || fseek(stream, 0, SEEK_SET)) return 9;
    char twice[1024];
    if (fread(twice, 1, (size_t)count * 2, stream) != (size_t)count * 2
        || memcmp(twice, buffer, count) || memcmp(twice + count, buffer, count) || fclose(stream)) return 10;
    stream = fopen(argv[1], "w");
    if (!stream || fgetc(stream) != EOF || !ferror(stream)) return 11;
    /* vfprintf may succeed while preserving an earlier sticky FILE error. */
    if (fprintf(stream, "%s/%p", "ok", (void *)0) != 4 || !ferror(stream) || fclose(stream)) return 12;
    errno = 0;
    if (dprintf(-1, "%s", "failure") != -1 || errno != EBADF) return 13;
    errno = 0;
    if (dprintf(-1, "") != -1 || errno != EBADF) return 20;
    errno = 0;
    if (dprintf(-1, "%Q") != -1 || errno != EINVAL) return 21;
    stream = fopen(argv[1], "w");
    if (!stream || setvbuf(stream, NULL, _IONBF, 0) || close(fileno(stream))) return 22;
    errno = 0;
    if (fprintf(stream, "") != -1 || errno != EBADF || !ferror(stream)) return 23;
    if (freopen(argv[1], "w", stream) != stream || fputs("after", stream) < 0
        || lseek(fileno(stream), 0, SEEK_CUR) != 5 || fclose(stream)) return 24;
    allocated = (char *)(uintptr_t)1;
    errno = 0;
    if (asprintf(&allocated, "%Q") != -1 || errno != EINVAL || allocated != (char *)(uintptr_t)1) return 14;
    if (asprintf(&allocated, "%cTAIL", 0) != 5 || !allocated || memcmp(allocated, "\0TAIL\0", 6)) return 15;
    free(allocated);
    stored = 123;
    errno = 0;
    if (snprintf(buffer, sizeof buffer, "%2147483648d%n", 1, &stored) != -1
        || errno != EOVERFLOW || stored != 123 || buffer[0]) return 16;
    errno = 0;
    if (snprintf(buffer, sizeof buffer, "%2$d", 1, 2) != -1 || errno != EINVAL || buffer[0]) return 17;
#ifdef CRABC_OWNED_PRINTF
    /* Defined owned diagnostics for invalid argument-class conflicts and
     * still-unimplemented wide grammar, not musl parity claims. */
    errno = 0;
    if (snprintf(buffer, sizeof buffer, "%1$d/%1$a") != -1 || errno != EINVAL || buffer[0]) return 26;
    errno = 0;
    if (snprintf(buffer, sizeof buffer, "%ls", L"wide") != -1 || errno != EINVAL || buffer[0]) return 27;
#endif
    if (snprintf(buffer, sizeof buffer, "%jd/%td/%hhu/%hu", (intmax_t)INT64_MIN,
        (ptrdiff_t)-7, 257, 65537) != 27 || strcmp(buffer, "-9223372036854775808/-7/1/1")) return 18;
    if (printf("owned-printf-ok\n") != 16) return 19;
    return 0;
}
