/* Static x86-64 sendfile fixture shared by pinned musl and crabc-libc.
 *
 * Raw syscalls own only fixture setup, observation, and cleanup. Each
 * sendfile result is checked against the regular-file contract and written
 * as a physical record for a byte-for-byte pinned-musl comparison.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(SYS_sendfile == 40 && SYS_open == 2 && SYS_close == 3 &&
    SYS_read == 0 && SYS_write == 1 && SYS_lseek == 8 && SYS_dup == 32 &&
    SYS_pread64 == 17 && SYS_getpid == 39 && SYS_unlink == 87,
    "x86 sendfile fixture syscalls");
_Static_assert(sizeof(off_t) == sizeof(int64_t) && (off_t)-1 < 0,
    "signed 64-bit off_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendfile),
    ssize_t (*)(int, int, off_t *, size_t)), "sendfile declaration");

static long raw0(long n) { long r; __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory"); return r; }
static long raw1(long n, long a) { long r; __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx", "r11", "memory"); return r; }
static long raw3(long n, long a, long b, long c) { long r; __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory"); return r; }

static int path(char *p, size_t n, long pid, char prefix)
{
    static const char a[] = ".work/x86_64/tmp/crabc-sendfile-";
    char digits[20];
    size_t i = 0;
    size_t prefix_length = 0;
    size_t digit_count = 0;
    unsigned long process_id = (unsigned long)pid;

    while (a[prefix_length] != '\0') {
        if (i + 1 >= n)
            return -1;
        p[i++] = a[prefix_length++];
    }
    if (i + 1 >= n)
        return -1;
    p[i++] = prefix;
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + process_id % 10);
        process_id /= 10;
    } while (process_id);
    while (digit_count) {
        if (i + 1 >= n)
            return -1;
        p[i++] = digits[--digit_count];
    }
    p[i] = '\0';
    return 0;
}

static int close_fd(int fd) { return fd >= 0 && raw1(SYS_close, fd) < 0 ? -1 : 0; }
static long current_position(int fd)
{
    return raw3(SYS_lseek, fd, 0, SEEK_CUR);
}

static int check_bytes(int fd, const char *expected, size_t n)
{
    char observed[16]; long got;
    register long offset __asm__("r10") = 0;
    __asm__ volatile("syscall" : "=a"(got)
        : "a"(SYS_pread64), "D"((long)fd), "S"((long)(void *)observed),
          "d"((long)n), "r"(offset) : "rcx", "r11", "memory");
    size_t i; if (got != (long)n) return -1;
    for (i = 0; i < n; ++i) if (observed[i] != expected[i]) return -1;
    return 0;
}

static size_t append_text(char *buffer, size_t used, const char *text)
{
    while (*text)
        buffer[used++] = *text++;
    return used;
}

static size_t append_number(char *buffer, size_t used, long value)
{
    char reverse[24];
    size_t count = 0;
    unsigned long magnitude;

    if (value < 0) {
        buffer[used++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        reverse[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    while (count)
        buffer[used++] = reverse[--count];
    return used;
}

static int record_case(const char *name, long value, int error, off_t *offset,
    int input, int output)
{
    char record[160];
    size_t used = 0;

    used = append_text(record, used, "case=");
    used = append_text(record, used, name);
    used = append_text(record, used, " value=");
    used = append_number(record, used, value);
    used = append_text(record, used, " errno=");
    used = append_number(record, used, error);
    used = append_text(record, used, " offset=");
    if (offset)
        used = append_number(record, used, *offset);
    else
        used = append_text(record, used, "null");
    used = append_text(record, used, " input=");
    used = append_number(record, used, current_position(input));
    used = append_text(record, used, " output=");
    used = append_number(record, used, current_position(output));
    record[used++] = '\n';
    return raw3(SYS_write, 1, (long)(void *)record, used) == (long)used ? 0 : -1;
}

int crabc_x86_64_sendfile_probe(void)
{
    static const char payload[] = "0123456789";
    static const char expected[] = "234589";
    char input_path[96], output_path[96];
    off_t explicit_offset = 2, zero_offset = 6, beyond_offset = 12;
    off_t invalid_offset = -1, bad_output_offset = 3;
    int input = -1, output = -1, closed = -1, closed_output = -1, result = 0;
    long transferred;

    if (path(input_path, sizeof(input_path), raw0(SYS_getpid), 'i') != 0 ||
        path(output_path, sizeof(output_path), raw0(SYS_getpid), 'o') != 0)
        return 10;
    input = (int)raw3(SYS_open, (long)(void *)input_path, O_CREAT|O_EXCL|O_RDWR, 0600);
    output = (int)raw3(SYS_open, (long)(void *)output_path, O_CREAT|O_EXCL|O_RDWR, 0600);
    if (input < 0 || output < 0) { result = 11; goto cleanup; }
    if (raw3(SYS_write, input, (long)(void *)payload, sizeof(payload)-1) != 10 ||
        raw3(SYS_lseek, input, 8, SEEK_SET) != 8) { result = 12; goto cleanup; }

    errno = ERANGE;
    transferred = sendfile(output, input, &explicit_offset, 4);
    if (record_case("explicit", transferred, errno, &explicit_offset, input, output)) { result = 13; goto cleanup; }
    if (transferred != 4 || explicit_offset != 6 || current_position(input) != 8 || errno != ERANGE) { result = 13; goto cleanup; }
    if (check_bytes(output, "2345", 4) != 0) { result = 14; goto cleanup; }
    if (raw3(SYS_lseek, output, 4, SEEK_SET) != 4) { result = 15; goto cleanup; }

    errno = EDOM;
    transferred = sendfile(output, input, (off_t *)0, 4);
    if (record_case("short", transferred, errno, (off_t *)0, input, output)) { result = 16; goto cleanup; }
    if (transferred != 2 || current_position(input) != 10 || current_position(output) != 6 || errno != EDOM) { result = 16; goto cleanup; }
    errno = E2BIG;
    transferred = sendfile(output, input, (off_t *)0, 1);
    if (record_case("eof", transferred, errno, (off_t *)0, input, output)) { result = 17; goto cleanup; }
    if (transferred != 0 || current_position(input) != 10 || current_position(output) != 6 || errno != E2BIG) { result = 17; goto cleanup; }
    if (check_bytes(output, expected, 6) != 0) { result = 18; goto cleanup; }

    errno = ENOTTY;
    transferred = sendfile(output, input, &zero_offset, 0);
    if (record_case("zero-count", transferred, errno, &zero_offset, input, output)) { result = 22; goto cleanup; }
    if (transferred != 0 || zero_offset != 6 || current_position(input) != 10 || current_position(output) != 6 || errno != ENOTTY) { result = 22; goto cleanup; }

    errno = ENOTTY;
    transferred = sendfile(output, input, &beyond_offset, 4);
    if (record_case("beyond-eof", transferred, errno, &beyond_offset, input, output)) { result = 23; goto cleanup; }
    if (transferred != 0 || beyond_offset != 12 || current_position(input) != 10 || current_position(output) != 6 || errno != ENOTTY) { result = 23; goto cleanup; }

    errno = EDOM;
    transferred = sendfile(output, input, &invalid_offset, 1);
    if (record_case("negative-offset", transferred, errno, &invalid_offset, input, output)) { result = 19; goto cleanup; }
    if (transferred != -1 || errno != EINVAL || invalid_offset != -1 || current_position(input) != 10 || current_position(output) != 6) { result = 19; goto cleanup; }
    closed = (int)raw1(SYS_dup, input);
    if (closed < 0 || close_fd(closed) != 0) { result = 20; goto cleanup; }
    errno = E2BIG;
    transferred = sendfile(output, closed, (off_t *)0, 1);
    if (record_case("closed-input", transferred, errno, (off_t *)0, input, output)) { result = 21; goto cleanup; }
    if (transferred != -1 || errno != EBADF || current_position(input) != 10 || current_position(output) != 6) { result = 21; goto cleanup; }

    closed_output = (int)raw1(SYS_dup, output);
    if (closed_output < 0 || close_fd(closed_output) != 0) { result = 24; goto cleanup; }
    errno = E2BIG;
    transferred = sendfile(closed_output, input, &bad_output_offset, 1);
    if (record_case("closed-output", transferred, errno, &bad_output_offset, input, output)) { result = 25; goto cleanup; }
    if (transferred != -1 || errno != EBADF || bad_output_offset != 3 || current_position(input) != 10 || current_position(output) != 6 || check_bytes(output, expected, 6) != 0) { result = 25; goto cleanup; }

cleanup:
    (void)close_fd(closed_output); (void)close_fd(closed); (void)close_fd(input); (void)close_fd(output);
    (void)raw1(SYS_unlink, (long)(void *)input_path);
    (void)raw1(SYS_unlink, (long)(void *)output_path);
    return result;
}

#ifndef CRABC_SENDFILE_FREESTANDING
int main(void) { return crabc_x86_64_sendfile_probe(); }
#endif
