/* Static crabc-libc x86-64 selected descriptor-I/O fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects descriptor transfer, positioning, truncation,
 * synchronization requests, duplication, and pipe construction. Fixture-local
 * raw memfd_create and fcntl calls create anonymous regular files and inspect
 * descriptor/status flags; they do not select C pathname/open/fcntl APIs,
 * stdio, CRT, pthread cancellation, AIO coordination, loader, sysroot, or
 * public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4 && sizeof(off_t) == 8 && sizeof(ssize_t) == 8,
    "x86 descriptor scalar widths");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_lseek == 8 && SYS_pread64 == 17 && SYS_pwrite64 == 18 &&
    SYS_pipe == 22 && SYS_dup == 32 && SYS_dup2 == 33 && SYS_fsync == 74 &&
    SYS_fdatasync == 75 && SYS_ftruncate == 77 && SYS_dup3 == 292 &&
    SYS_pipe2 == 293 && SYS_memfd_create == 319 && SYS_pwritev2 == 328,
    "x86 selected descriptor-I/O syscall numbers");
_Static_assert(O_APPEND == 02000 && O_NONBLOCK == 04000 &&
    O_CLOEXEC == 02000000 && F_GETFD == 1 && F_GETFL == 3 && F_SETFL == 4 &&
    FD_CLOEXEC == 1 && SEEK_SET == 0 && SEEK_CUR == 1 && SEEK_END == 2,
    "x86 selected descriptor-I/O constants");
_Static_assert(MFD_CLOEXEC == 0x0001U, "x86 memfd CLOEXEC fixture flag");
_Static_assert(__builtin_types_compatible_p(__typeof__(&close),
    int (*)(int)), "close declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&read),
    ssize_t (*)(int, void *, size_t)), "read declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&write),
    ssize_t (*)(int, const void *, size_t)), "write declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pread),
    ssize_t (*)(int, void *, size_t, off_t)), "pread declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwrite),
    ssize_t (*)(int, const void *, size_t, off_t)), "pwrite declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lseek),
    off_t (*)(int, off_t, int)), "lseek declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ftruncate),
    int (*)(int, off_t)), "ftruncate declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fsync),
    int (*)(int)), "fsync declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fdatasync),
    int (*)(int)), "fdatasync declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dup),
    int (*)(int)), "dup declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dup2),
    int (*)(int, int)), "dup2 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dup3),
    int (*)(int, int, int)), "dup3 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pipe),
    int (*)(int *)), "pipe declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pipe2),
    int (*)(int *, int)), "pipe2 declaration");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 vector record layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readv),
    ssize_t (*)(int, const struct iovec *, int)), "readv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&writev),
    ssize_t (*)(int, const struct iovec *, int)), "writev declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&preadv),
    ssize_t (*)(int, const struct iovec *, int, off_t)), "preadv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwritev),
    ssize_t (*)(int, const struct iovec *, int, off_t)), "pwritev declaration");

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_memfd_create(const char *name, unsigned flags)
{
    return (int)raw_syscall2(SYS_memfd_create, (long)name, flags);
}

static int raw_fcntl(int file_descriptor, int command, long argument)
{
    return (int)raw_syscall3(SYS_fcntl, file_descriptor, command, argument);
}

static void raw_close(int file_descriptor)
{
    if (file_descriptor >= 0)
        (void)raw_syscall1(SYS_close, file_descriptor);
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

/* Record measured values through a fixture-local raw write, so the two libc
 * implementations cannot substitute a common output function for the calls
 * under test. Each line is small enough for one regular-file write. */
static int trace_value(const char *name, long value)
{
    char line[96];
    char digits[24];
    unsigned long magnitude;
    size_t length = 0;
    size_t count = 0;
    int negative = value < 0;

    while (*name)
        line[length++] = *name++;
    line[length++] = '=';
    magnitude = negative ? 0UL - (unsigned long)value : (unsigned long)value;
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    if (negative)
        line[length++] = '-';
    while (count)
        line[length++] = digits[--count];
    line[length++] = '\n';
    return raw_syscall3(SYS_write, 1, (long)line, length) == (long)length;
}

static int trace_bytes(const char *name, const char *bytes, size_t count)
{
    static const char hex[] = "0123456789abcdef";
    char line[96];
    size_t length = 0;
    size_t index;

    while (*name)
        line[length++] = *name++;
    line[length++] = '=';
    for (index = 0; index < count; ++index) {
        unsigned char byte = (unsigned char)bytes[index];
        line[length++] = hex[byte >> 4];
        line[length++] = hex[byte & 15];
    }
    line[length++] = '\n';
    return raw_syscall3(SYS_write, 1, (long)line, length) == (long)length;
}

static int trace_error(const char *name, ssize_t result, int expected_errno)
{
    return trace_value(name, result) && trace_value("errno", errno) &&
        result == -1 && errno == expected_errno;
}

static int trace_offset(int descriptor, const char *name, off_t expected)
{
    off_t observed = lseek(descriptor, 0, SEEK_CUR);

    return trace_value(name, observed) && observed == expected;
}

/* A single open file description mixes scalar and vector operations. Regular
 * file EOF makes short reads deterministic; a nonblocking pipe proves the
 * same transfer boundary without depending on its capacity or scheduling. */
static int check_scalar_vector_composition(void)
{
    char buffer[8] = { 0 };
    char first[2] = { 0, 0 };
    char second[6] = { 0, 0, 0, 0, 0, 0 };
    struct iovec write_parts[2] = { { (void *)"cd", 2 }, { (void *)"ef", 2 } };
    struct iovec read_parts[2] = { { first, 2 }, { second, 6 } };
    struct iovec positioned_parts[2] = { { (void *)"Y", 1 }, { (void *)"Z", 1 } };
    int descriptor = -1;
    int ends[2] = { -1, -1 };
    ssize_t result;
    int status = 0;

    descriptor = raw_memfd_create("crabc-scalar-vector", 0);
    if (descriptor < 0)
        return 1;
    result = write(descriptor, "ab", 2);
    if (!trace_value("file.write", result) || result != 2 ||
        !trace_offset(descriptor, "file.offset.after.write", 2)) { status = 2; goto finish; }
    result = writev(descriptor, write_parts, 2);
    if (!trace_value("file.writev", result) || result != 4 ||
        !trace_offset(descriptor, "file.offset.after.writev", 6)) { status = 3; goto finish; }
    if (lseek(descriptor, 1, SEEK_SET) != 1) { status = 4; goto finish; }
    result = readv(descriptor, read_parts, 2);
    if (!trace_value("file.readv.short", result) ||
        !trace_bytes("file.readv.bytes", first, 2) ||
        !trace_bytes("file.readv.tail", second, 3) ||
        result != 5 || !bytes_equal(first, "bc", 2) ||
        !bytes_equal(second, "def", 3) || second[3] != 0 ||
        !trace_offset(descriptor, "file.offset.after.readv", 6)) { status = 5; goto finish; }
    result = pread(descriptor, buffer, 4, 2);
    if (!trace_value("file.pread", result) ||
        !trace_bytes("file.pread.bytes", buffer, 4) || result != 4 ||
        !bytes_equal(buffer, "cdef", 4) ||
        !trace_offset(descriptor, "file.offset.after.pread", 6)) { status = 6; goto finish; }
    result = preadv(descriptor, read_parts, 2, 4);
    if (!trace_value("file.preadv.short", result) ||
        !trace_bytes("file.preadv.bytes", first, 2) || result != 2 ||
        !bytes_equal(first, "ef", 2) ||
        !trace_offset(descriptor, "file.offset.after.preadv", 6)) { status = 7; goto finish; }
    result = pwrite(descriptor, "X", 1, 1);
    if (!trace_value("file.pwrite", result) || result != 1 ||
        !trace_offset(descriptor, "file.offset.after.pwrite", 6)) { status = 8; goto finish; }
    result = pwritev(descriptor, positioned_parts, 2, 3);
    if (!trace_value("file.pwritev", result) || result != 2 ||
        !trace_offset(descriptor, "file.offset.after.pwritev", 6)) { status = 9; goto finish; }
    if (lseek(descriptor, 0, SEEK_SET) != 0) { status = 10; goto finish; }
    result = read(descriptor, buffer, sizeof(buffer));
    if (!trace_value("file.read.short", result) ||
        !trace_bytes("file.read.bytes", buffer, 6) || result != 6 ||
        !bytes_equal(buffer, "aXcYZf", 6) ||
        !trace_offset(descriptor, "file.offset.after.read", 6)) { status = 11; goto finish; }
    result = writev(descriptor, write_parts, 0);
    if (!trace_value("file.writev.empty", result) || result != 0 ||
        !trace_offset(descriptor, "file.offset.after.empty", 6)) { status = 12; goto finish; }
    result = read(descriptor, buffer, 1);
    if (!trace_value("file.read.eof", result) || result != 0 ||
        !trace_offset(descriptor, "file.offset.after.eof", 6)) { status = 24; goto finish; }

    errno = 0;
    result = read(-1, buffer, 1);
    if (!trace_error("error.read.badfd", result, EBADF)) { status = 13; goto finish; }
    errno = 0;
    result = write(-1, "X", 1);
    if (!trace_error("error.write.badfd", result, EBADF)) { status = 25; goto finish; }
    errno = 0;
    result = readv(-1, read_parts, 2);
    if (!trace_error("error.readv.badfd", result, EBADF)) { status = 26; goto finish; }
    errno = 0;
    result = writev(-1, write_parts, 2);
    if (!trace_error("error.writev.badfd", result, EBADF)) { status = 14; goto finish; }
    errno = 0;
    result = writev(descriptor, write_parts, -1);
    if (!trace_error("error.writev.count", result, EINVAL)) { status = 27; goto finish; }
    errno = 0;
    result = pread(descriptor, buffer, 1, -1);
    if (!trace_error("error.pread.offset", result, EINVAL)) { status = 15; goto finish; }
    errno = 0;
    result = pwrite(-1, "X", 1, 0);
    if (!trace_error("error.pwrite.badfd", result, EBADF)) { status = 28; goto finish; }
    errno = 0;
    result = preadv(-1, read_parts, 2, 0);
    if (!trace_error("error.preadv.badfd", result, EBADF)) { status = 29; goto finish; }
    errno = 0;
    result = preadv(descriptor, read_parts, -1, 0);
    if (!trace_error("error.preadv.count", result, EINVAL)) { status = 16; goto finish; }
    errno = 0;
    result = pwritev(descriptor, positioned_parts, 2, -1);
    if (!trace_error("error.pwritev.offset", result, EINVAL) ||
        !trace_offset(descriptor, "file.offset.after.errors", 6)) { status = 17; goto finish; }

    if (pipe2(ends, O_NONBLOCK) != 0) { status = 18; goto finish; }
    result = write(ends[1], "123", 3);
    if (!trace_value("pipe.write", result) || result != 3) { status = 19; goto finish; }
    result = readv(ends[0], read_parts, 2);
    if (!trace_value("pipe.readv.short", result) ||
        !trace_bytes("pipe.readv.bytes", first, 2) ||
        !trace_bytes("pipe.readv.tail", second, 1) ||
        result != 3 || !bytes_equal(first, "12", 2) || second[0] != '3') {
        status = 20; goto finish;
    }
    errno = 0;
    result = read(ends[0], buffer, 1);
    if (!trace_error("pipe.read.empty", result, EAGAIN)) { status = 21; goto finish; }
    result = writev(ends[1], positioned_parts, 2);
    if (!trace_value("pipe.writev", result) || result != 2) { status = 22; goto finish; }
    result = read(ends[0], buffer, sizeof(buffer));
    if (!trace_value("pipe.read.short", result) ||
        !trace_bytes("pipe.read.bytes", buffer, 2) || result != 2 ||
        !bytes_equal(buffer, "YZ", 2)) status = 23;

finish:
    raw_close(ends[0]);
    raw_close(ends[1]);
    raw_close(descriptor);
    return status;
}

static int check_transfer_position_truncate_and_sync(void)
{
    static const char initial[] = "abcd";
    static const char expected[] = "ZbQd";
    char buffer[4];
    char zeros[3];
    int file_descriptor = -1;
    int status = 0;

    file_descriptor = raw_memfd_create("crabc-descriptor-io", 0);
    if (file_descriptor < 0)
        return 1;
    if (write(file_descriptor, initial, sizeof(initial) - 1) != 4 ||
        lseek(file_descriptor, 0, SEEK_CUR) != 4) {
        status = 2;
        goto finish;
    }
    if (lseek(file_descriptor, 0, SEEK_SET) != 0 ||
        read(file_descriptor, buffer, sizeof(buffer)) != 4 ||
        !bytes_equal(buffer, initial, sizeof(buffer))) {
        status = 3;
        goto finish;
    }
    if (lseek(file_descriptor, 2, SEEK_SET) != 2 ||
        pwrite(file_descriptor, "Z", 1, 0) != 1 ||
        lseek(file_descriptor, 0, SEEK_CUR) != 2 ||
        write(file_descriptor, "Q", 1) != 1 ||
        pread(file_descriptor, buffer, sizeof(buffer), 0) != 4 ||
        !bytes_equal(buffer, expected, sizeof(buffer)) ||
        lseek(file_descriptor, 0, SEEK_CUR) != 3) {
        status = 4;
        goto finish;
    }
    if (ftruncate(file_descriptor, 7) != 0 ||
        lseek(file_descriptor, 0, SEEK_CUR) != 3 ||
        pread(file_descriptor, zeros, sizeof(zeros), 4) != 3 ||
        zeros[0] != 0 || zeros[1] != 0 || zeros[2] != 0) {
        status = 5;
        goto finish;
    }
    if (ftruncate(file_descriptor, 2) != 0 ||
        lseek(file_descriptor, 0, SEEK_CUR) != 3 ||
        pread(file_descriptor, buffer, 1, 2) != 0) {
        status = 6;
        goto finish;
    }
    if (fsync(file_descriptor) != 0 || lseek(file_descriptor, 0, SEEK_CUR) != 3 ||
        fdatasync(file_descriptor) != 0 ||
        lseek(file_descriptor, 0, SEEK_CUR) != 3) {
        status = 7;
        goto finish;
    }

    if (lseek(file_descriptor, 0, SEEK_SET) != 0) {
        status = 8;
        goto finish;
    }
    errno = 0;
    if (read(-1, buffer, 1) != -1 || errno != EBADF) {
        status = 9;
        goto finish;
    }
    errno = 0;
    if (read(file_descriptor, NULL, 1) != -1 || errno != EFAULT) {
        status = 10;
        goto finish;
    }
    errno = 0;
    if (write(file_descriptor, NULL, 1) != -1 || errno != EFAULT) {
        status = 11;
        goto finish;
    }
    errno = 0;
    if (pread(file_descriptor, NULL, 1, 0) != -1 || errno != EFAULT) {
        status = 12;
        goto finish;
    }
    errno = 0;
    if (pwrite(file_descriptor, NULL, 1, 0) != -1 || errno != EFAULT) {
        status = 13;
        goto finish;
    }
    errno = 0;
    if (pread(file_descriptor, buffer, 1, -1) != -1 || errno != EINVAL) {
        status = 14;
        goto finish;
    }
    errno = 0;
    if (pwrite(file_descriptor, "X", 1, -1) != -1 || errno != EINVAL) {
        status = 15;
        goto finish;
    }
    errno = 0;
    if (lseek(file_descriptor, -1, SEEK_SET) != (off_t)-1 || errno != EINVAL) {
        status = 16;
        goto finish;
    }
    errno = 0;
    if (lseek(file_descriptor, 0, 99) != (off_t)-1 || errno != EINVAL) {
        status = 17;
        goto finish;
    }
    errno = 0;
    if (ftruncate(file_descriptor, -1) != -1 || errno != EINVAL) {
        status = 18;
        goto finish;
    }
    errno = 0;
    if (fsync(-1) != -1 || errno != EBADF) {
        status = 19;
        goto finish;
    }
    errno = 0;
    if (fdatasync(-1) != -1 || errno != EBADF)
        status = 20;

finish:
    raw_close(file_descriptor);
    return status;
}

static int check_pwrite_append_boundary(void)
{
    static const char initial[] = "ABCD";
    char observed = 0;
    int file_descriptor = -1;
    int original_flags;
    ssize_t result;
    int status = 0;

    file_descriptor = raw_memfd_create("crabc-pwrite-append", 0);
    if (file_descriptor < 0)
        return 1;
    if (write(file_descriptor, initial, sizeof(initial) - 1) != 4 ||
        lseek(file_descriptor, 4, SEEK_SET) != 4) {
        status = 2;
        goto finish;
    }
    original_flags = raw_fcntl(file_descriptor, F_GETFL, 0);
    if (original_flags < 0 ||
        raw_fcntl(file_descriptor, F_SETFL, original_flags | O_APPEND) != 0) {
        status = 3;
        goto finish;
    }
    errno = 0;
    result = pwrite(file_descriptor, "Z", 1, 0);
    if (result == 1) {
        if (pread(file_descriptor, &observed, 1, 0) != 1 || observed != 'Z' ||
            lseek(file_descriptor, 0, SEEK_END) != 4) {
            status = 4;
            goto restore_flags;
        }
    } else if (result == -1 && errno == EOPNOTSUPP) {
        if (pread(file_descriptor, &observed, 1, 0) != 1 || observed != 'A' ||
            lseek(file_descriptor, 0, SEEK_END) != 4) {
            status = 5;
            goto restore_flags;
        }
    } else {
        status = 6;
        goto restore_flags;
    }

restore_flags:
    if (raw_fcntl(file_descriptor, F_SETFL, original_flags) != 0 && status == 0)
        status = 7;
finish:
    raw_close(file_descriptor);
    return status;
}

static int check_dup_and_close(void)
{
    int file_descriptor = -1;
    int duplicate = -1;
    char byte = 0;
    int status = 0;

    file_descriptor = raw_memfd_create("crabc-dup-close", MFD_CLOEXEC);
    if (file_descriptor < 0)
        return 1;
    if (raw_fcntl(file_descriptor, F_GETFD, 0) != FD_CLOEXEC ||
        write(file_descriptor, "xy", 2) != 2 ||
        lseek(file_descriptor, 0, SEEK_SET) != 0) {
        status = 2;
        goto finish;
    }
    duplicate = dup(file_descriptor);
    if (duplicate < 0 || duplicate == file_descriptor ||
        raw_fcntl(duplicate, F_GETFD, 0) != 0 ||
        read(duplicate, &byte, 1) != 1 || byte != 'x' ||
        lseek(file_descriptor, 0, SEEK_CUR) != 1) {
        status = 3;
        goto finish;
    }
    if (close(file_descriptor) != 0) {
        status = 4;
        goto finish;
    }
    file_descriptor = -1;
    if (read(duplicate, &byte, 1) != 1 || byte != 'y' ||
        close(duplicate) != 0) {
        status = 5;
        goto finish;
    }
    file_descriptor = duplicate;
    duplicate = -1;
    errno = 0;
    if (read(file_descriptor, &byte, 1) != -1 || errno != EBADF) {
        status = 6;
        goto finish;
    }
    file_descriptor = -1;
    errno = 0;
    if (close(-1) != -1 || errno != EBADF)
        status = 7;

finish:
    raw_close(duplicate);
    raw_close(file_descriptor);
    return status;
}

static int check_dup2_and_dup3(void)
{
    int source = -1;
    int target = -1;
    int zero_target = -1;
    int cloexec_target = -1;
    char byte = 0;
    int status = 0;

    source = raw_memfd_create("crabc-dup-source", 0);
    target = raw_memfd_create("crabc-dup-target", 0);
    if (source < 0 || target < 0) {
        status = 1;
        goto finish;
    }
    if (write(source, "AB", 2) != 2 || lseek(source, 0, SEEK_SET) != 0 ||
        write(target, "Q", 1) != 1 || dup2(source, target) != target ||
        read(target, &byte, 1) != 1 || byte != 'A' ||
        lseek(source, 0, SEEK_CUR) != 1 || dup2(source, source) != source) {
        status = 2;
        goto finish;
    }
    errno = 0;
    if (dup2(-1, -1) != -1 || errno != EBADF) {
        status = 3;
        goto finish;
    }

    zero_target = raw_memfd_create("crabc-dup3-zero", 0);
    if (zero_target < 0 || dup3(source, zero_target, 0) != zero_target ||
        raw_fcntl(zero_target, F_GETFD, 0) != 0) {
        status = 4;
        goto finish;
    }
    cloexec_target = raw_memfd_create("crabc-dup3-cloexec", 0);
    if (cloexec_target < 0 ||
        dup3(source, cloexec_target, O_CLOEXEC) != cloexec_target ||
        raw_fcntl(cloexec_target, F_GETFD, 0) != FD_CLOEXEC) {
        status = 5;
        goto finish;
    }
    errno = 0;
    if (dup3(source, source, O_CLOEXEC) != -1 || errno != EINVAL) {
        status = 6;
        goto finish;
    }
    errno = 0;
    if (dup3(source, cloexec_target, 1) != -1 || errno != EINVAL)
        status = 7;

finish:
    raw_close(cloexec_target);
    raw_close(zero_target);
    raw_close(target);
    raw_close(source);
    return status;
}

static int check_pipe_and_pipe2(void)
{
    int file_descriptors[2] = { -1, -1 };
    char byte = 0;
    int status = 0;

    if (pipe(file_descriptors) != 0 || file_descriptors[0] < 0 ||
        file_descriptors[1] < 0 || raw_fcntl(file_descriptors[0], F_GETFD, 0) != 0 ||
        raw_fcntl(file_descriptors[1], F_GETFD, 0) != 0 ||
        write(file_descriptors[1], "P", 1) != 1 ||
        read(file_descriptors[0], &byte, 1) != 1 || byte != 'P') {
        status = 1;
        goto finish;
    }
    raw_close(file_descriptors[0]);
    raw_close(file_descriptors[1]);
    file_descriptors[0] = -1;
    file_descriptors[1] = -1;

    if (pipe2(file_descriptors, 0) != 0 || file_descriptors[0] < 0 ||
        file_descriptors[1] < 0 || raw_fcntl(file_descriptors[0], F_GETFD, 0) != 0 ||
        raw_fcntl(file_descriptors[1], F_GETFD, 0) != 0) {
        status = 2;
        goto finish;
    }
    raw_close(file_descriptors[0]);
    raw_close(file_descriptors[1]);
    file_descriptors[0] = -1;
    file_descriptors[1] = -1;

    if (pipe2(file_descriptors, O_CLOEXEC | O_NONBLOCK) != 0 ||
        file_descriptors[0] < 0 || file_descriptors[1] < 0 ||
        raw_fcntl(file_descriptors[0], F_GETFD, 0) != FD_CLOEXEC ||
        raw_fcntl(file_descriptors[1], F_GETFD, 0) != FD_CLOEXEC ||
        (raw_fcntl(file_descriptors[0], F_GETFL, 0) & O_NONBLOCK) == 0 ||
        (raw_fcntl(file_descriptors[1], F_GETFL, 0) & O_NONBLOCK) == 0 ||
        write(file_descriptors[1], "R", 1) != 1 ||
        read(file_descriptors[0], &byte, 1) != 1 || byte != 'R') {
        status = 3;
        goto finish;
    }
    raw_close(file_descriptors[0]);
    raw_close(file_descriptors[1]);
    file_descriptors[0] = -1;
    file_descriptors[1] = -1;

    errno = 0;
    if (pipe(NULL) != -1 || errno != EFAULT) {
        status = 4;
        goto finish;
    }
    errno = 0;
    if (pipe2(NULL, 0) != -1 || errno != EFAULT) {
        status = 5;
        goto finish;
    }
    errno = 0;
    if (pipe2(file_descriptors, 0x40000000) != -1 || errno != EINVAL)
        status = 6;

finish:
    raw_close(file_descriptors[0]);
    raw_close(file_descriptors[1]);
    return status;
}

int crabc_x86_64_descriptor_io_probe(void)
{
    int status;

    status = check_transfer_position_truncate_and_sync();
    if (status != 0)
        return 10 + status;
    status = check_pwrite_append_boundary();
    if (status != 0)
        return 30 + status;
    status = check_dup_and_close();
    if (status != 0)
        return 50 + status;
    status = check_dup2_and_dup3();
    if (status != 0)
        return 70 + status;
    status = check_pipe_and_pipe2();
    if (status != 0)
        return 90 + status;
    status = check_scalar_vector_composition();
    if (status != 0)
        return 110 + status;
    return 0;
}

#ifndef CRABC_DESCRIPTOR_IO_FREESTANDING
int main(void)
{
    return crabc_x86_64_descriptor_io_probe();
}
#endif
