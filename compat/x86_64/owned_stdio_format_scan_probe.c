#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* The same installed-header object is linked against pinned musl and crabc. */
struct cookie {
    unsigned char bytes[128];
    size_t length;
    off_t position;
};

static ssize_t cookie_read(void *opaque, char *buffer, size_t count)
{
    struct cookie *cookie = opaque;
    if ((size_t)cookie->position >= cookie->length) return 0;
    if (count > cookie->length - (size_t)cookie->position)
        count = cookie->length - (size_t)cookie->position;
    memcpy(buffer, cookie->bytes + cookie->position, count);
    cookie->position += count;
    return (ssize_t)count;
}

static ssize_t cookie_write(void *opaque, const char *buffer, size_t count)
{
    struct cookie *cookie = opaque;
    if (count > sizeof cookie->bytes - (size_t)cookie->position) return -1;
    memcpy(cookie->bytes + cookie->position, buffer, count);
    cookie->position += count;
    if ((size_t)cookie->position > cookie->length) cookie->length = cookie->position;
    return (ssize_t)count;
}

static int cookie_seek(void *opaque, off_t *position, int whence)
{
    struct cookie *cookie = opaque;
    off_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? cookie->position : (off_t)cookie->length;
    off_t next = base + *position;
    if (next < 0 || next > (off_t)sizeof cookie->bytes) return -1;
    cookie->position = next;
    *position = next;
    return 0;
}

static int forwarded_print(FILE *file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vfprintf(file, format, args);
    va_end(args);
    return result;
}

static int forwarded_scan(FILE *file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vfscanf(file, format, args);
    va_end(args);
    return result;
}

static int forwarded_wprint(wchar_t *buffer, size_t capacity, const wchar_t *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vswprintf(buffer, capacity, format, args);
    va_end(args);
    return result;
}

static int forwarded_wscan(const wchar_t *source, const wchar_t *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vswscanf(source, format, args);
    va_end(args);
    return result;
}

static void dump(const char *label, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    printf("%s ", label);
    for (size_t index = 0; index < length; ++index) printf("%02x", bytes[index]);
    putchar('\n');
}

int main(void)
{
    char fixed[64] = {0};
    FILE *file = fmemopen(fixed, sizeof fixed, "w+");
    if (!file) return 1;
    int count = -1;
    errno = 0;
    int printed = forwarded_print(file, "[%#x|%+06d|%.2f]%n", 0x2a, 17, 1.25, &count);
    printf("fixed-print %d %d %d %ld\n", printed, count, errno, ftell(file));
    if (fflush(file) || fseek(file, 0, SEEK_SET)) return 2;
    unsigned hexadecimal = 0;
    int decimal = 0, consumed = -1;
    double real = 0;
    errno = 0;
    int scanned = forwarded_scan(file, "[0x%x|%d|%lf]%n", &hexadecimal, &decimal, &real, &consumed);
    printf("fixed-scan %d %x %d %.2f %d %d %ld\n", scanned, hexadecimal, decimal, real, consumed, errno, ftell(file));
    dump("fixed-bytes", fixed, 24);
    if (fclose(file)) return 3;

    char *grown = NULL;
    size_t grown_length = 0;
    file = open_memstream(&grown, &grown_length);
    if (!file) return 4;
    count = -1;
    errno = 0;
    printed = fprintf(file, "%-5s:%#o:%n%s", "ab", 075, &count, "done");
    if (fflush(file)) return 5;
    printf("grown-print %d %d %d %zu %ld\n", printed, count, errno, grown_length, ftell(file));
    dump("grown-bytes", grown, grown_length + 1);
    if (fclose(file)) return 6;
    free(grown);

    struct cookie state = {0};
    cookie_io_functions_t operations = {cookie_read, cookie_write, cookie_seek, NULL};
    file = fopencookie(&state, "w+", operations);
    if (!file) return 7;
    if (setvbuf(file, NULL, _IONBF, 0)) return 8;
    errno = 0;
    printed = fprintf(file, "%4d/%s/%a", 23, "xy", 1.5);
    printf("cookie-print %d %d %ld\n", printed, errno, ftell(file));
    if (fseek(file, 0, SEEK_SET)) return 9;
    char word[8] = {0};
    decimal = 0; real = 0; consumed = -1;
    errno = 0;
    scanned = fscanf(file, "%d/%2s/%la%n", &decimal, word, &real, &consumed);
    printf("cookie-scan %d %d %s %.2f %d %d %ld %d\n", scanned, decimal, word, real, consumed, errno, ftell(file), feof(file));
    dump("cookie-bytes", state.bytes, state.length);
    if (fclose(file)) return 10;

    wchar_t wide[64];
    for (size_t index = 0; index < 64; ++index) wide[index] = 0x5a5a;
    count = -1;
    errno = 0;
    printed = forwarded_wprint(wide, 64, L"%+06d/%ls%n", 27, L"wide", &count);
    printf("wide-print %d %d %d %x %x %x\n", printed, count, errno, (unsigned)wide[0], (unsigned)wide[7], (unsigned)wide[printed]);
    wchar_t word_wide[16] = {0};
    decimal = 0; consumed = -1;
    errno = 0;
    scanned = forwarded_wscan(wide, L"%d/%ls%n", &decimal, word_wide, &consumed);
    printf("wide-scan %d %d %x %d %d\n", scanned, decimal, (unsigned)word_wide[0], consumed, errno);
    return 0;
}
