#define _GNU_SOURCE
#include <errno.h>
#include <locale.h>
#include <pthread.h>
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

struct scan_fault_cookie {
    const char *bytes;
    size_t position;
    size_t length;
    size_t fail_after;
};

static ssize_t scan_fault_read(void *opaque, char *buffer, size_t count)
{
    struct scan_fault_cookie *cookie = opaque;
    if (!count || cookie->position == cookie->length) return 0;
    if (cookie->position == cookie->fail_after) {
        errno = EIO;
        return -1;
    }
    if (count > 1) count = 1;
    *buffer = cookie->bytes[cookie->position++];
    return 1;
}

static int scan_stream_boundaries(void)
{
    char digits[] = "12x";
    FILE *file = fmemopen(digits, 3, "r");
    if (!file) return 11;
    int value = -1, consumed = -1;
    errno = EDOM;
    int assigned = forwarded_scan(file, "%d%n", &value, &consumed);
    int scan_errno = errno;
    long position = ftell(file);
    int next = fgetc(file);
    int failed = ferror(file);
    printf("scan-lookahead %d %d %d %d %ld %d %d\n", assigned, value,
        consumed, scan_errno, position, next, failed);
    if (fclose(file)) return 12;

    struct scan_fault_cookie cookie = { "12 34", 0, 5, 3 };
    cookie_io_functions_t operations = { scan_fault_read, NULL, NULL, NULL };
    file = fopencookie(&cookie, "r", operations);
    if (!file) return 13;
    if (setvbuf(file, NULL, _IONBF, 0)) return 14;
    int second = -1;
    consumed = -1;
    errno = 0;
    assigned = forwarded_scan(file, "%d %d%n", &value, &second, &consumed);
    printf("scan-read-error %d %d %d %d %d %d %zu\n", assigned, value,
        second, consumed, errno, ferror(file), cookie.position);
    if (fclose(file)) return 15;

    char allocation_input[] = "ab cd";
    file = fmemopen(allocation_input, sizeof allocation_input - 1, "r");
    if (!file) return 16;
    char *allocated = NULL;
    consumed = -1;
    errno = EDOM;
    assigned = forwarded_scan(file, "%ms %*s%n", &allocated, &consumed);
    scan_errno = errno;
    position = ftell(file);
    printf("scan-allocation %d %s %d %d %ld\n", assigned,
        allocated ? allocated : "(null)", consumed, scan_errno, position);
    free(allocated);
    if (fclose(file)) return 17;

    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 18;
    char utf8[] = { '7', ' ', (char)0xc3, (char)0xa9, 'X' };
    file = fmemopen(utf8, sizeof utf8, "r");
    if (!file) return 19;
    wchar_t wide[8] = { 0x7777 };
    value = -1;
    consumed = -1;
    errno = EDOM;
    assigned = forwarded_scan(file, "%d %ls%n", &value, wide, &consumed);
    scan_errno = errno;
    position = ftell(file);
    printf("scan-locale-valid %d %d %x %x %x %d %d %ld\n", assigned,
        value, (unsigned)wide[0], (unsigned)wide[1], (unsigned)wide[2],
        consumed, scan_errno, position);
    if (fclose(file)) return 20;

    char malformed[] = { '7', ' ', (char)0xc3, 'x' };
    file = fmemopen(malformed, sizeof malformed, "r");
    if (!file) return 21;
    for (size_t index = 0; index < 8; ++index) wide[index] = 0x7777;
    value = -1;
    consumed = -1;
    errno = 0;
    assigned = forwarded_scan(file, "%d %ls%n", &value, wide, &consumed);
    scan_errno = errno;
    position = ftell(file);
    failed = ferror(file);
    printf("scan-locale-error %d %d %x %d %d %ld %d\n", assigned,
        value, (unsigned)wide[0], consumed, scan_errno, position, failed);
    if (fclose(file)) return 22;
    if (!setlocale(LC_CTYPE, "C")) return 23;
    return 0;
}

static void dump(const char *label, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    printf("%s ", label);
    for (size_t index = 0; index < length; ++index) printf("%02x", bytes[index]);
    putchar('\n');
}

/* All storage and the locale token outlive the joined worker. No stream
 * operation overlaps another thread's access, and only byte I/O or %ls
 * conversion is used on the retained byte-oriented stream. */
struct retained_format {
    FILE *file;
    locale_t locale;
    char short_text[5];
    int printed, counted, print_errno, flushed, oriented;
    int bounded, bounded_count, bounded_errno;
};

static void *format_worker(void *opaque)
{
    struct retained_format *state = opaque;
    if (!uselocale(state->locale)) pthread_exit((void *)1);
    errno = ERANGE;
    state->printed = forwarded_print(state->file, "%+d/%.2f/%ls%n!",
        27, 1.25, L"\u00e9X", &state->counted);
    state->print_errno = errno;
    state->flushed = fflush(state->file);
    state->oriented = fwide(state->file, 0) < 0;
    errno = EDOM;
    state->bounded = snprintf(state->short_text, sizeof state->short_text,
        "%d/%ls%n", 27, L"\u00e9X", &state->bounded_count);
    state->bounded_errno = errno;
    pthread_exit(NULL);
}

static int retained_worker_format(void)
{
    char bytes[128] = {0}, stream_buffer[32];
    struct retained_format state = {0};
    locale_t utf8 = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    locale_t byte = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (!utf8 || !byte) return 30;
    locale_t previous = uselocale(byte);
    if (!previous) return 31;
    state.locale = utf8;
    state.file = fmemopen(bytes, sizeof bytes, "w+");
    if (!state.file || setvbuf(state.file, stream_buffer, _IOFBF,
            sizeof stream_buffer)) return 32;
    pthread_t worker;
    void *result = (void *)1;
    errno = EDOM;
    if (pthread_create(&worker, NULL, format_worker, &state) ||
            pthread_join(worker, &result) || result) return 33;
    int parent_errno = errno;
    if (state.printed < 0 || (size_t)state.printed >= sizeof bytes) return 36;
    printf("worker-print %d %d %d %d %d %d %ld\n", state.printed,
        state.counted, state.print_errno, state.flushed, state.oriented,
        parent_errno, ftell(state.file));
    printf("worker-bounded %d %d %d\n", state.bounded,
        state.bounded_count, state.bounded_errno);
    dump("worker-bounded-bytes", state.short_text, sizeof state.short_text);
    dump("worker-stream-bytes", bytes, (size_t)state.printed + 1);

    /* The caller's current locale governs %ls on a byte stream, including
     * one oriented in another thread whose locale state has been retired. */
    for (int unicode = 0; unicode < 2; ++unicode) {
        if (!uselocale(unicode ? utf8 : byte) ||
                fseek(state.file, 0, SEEK_SET)) return 34;
        int decimal = -1, consumed = -1;
        double real = -1;
        wchar_t text[8] = {0};
        errno = EDOM;
        int assigned = forwarded_scan(state.file, unicode ? "%d/%lf/%2ls%n" : "%d/%lf/%3ls%n",
            &decimal, &real, text, &consumed);
        int scan_errno = errno;
        long position = ftell(state.file);
        int next = fgetc(state.file);
        printf("worker-scan %d %d %d %.2f %x %x %x %x %d %d %ld %d %d %d\n",
            unicode, assigned, decimal, real, (unsigned)text[0],
            (unsigned)text[1], (unsigned)text[2], (unsigned)text[3], consumed,
            scan_errno, position, next, ferror(state.file), fwide(state.file, 0) < 0);
    }
    if (fclose(state.file) || !uselocale(previous)) return 35;
    freelocale(byte);
    freelocale(utf8);
    return 0;
}

int main(void)
{
    int retained_status = retained_worker_format();
    if (retained_status) return retained_status;
    int scan_status = scan_stream_boundaries();
    if (scan_status) return scan_status;
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
