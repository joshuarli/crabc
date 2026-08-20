#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern ssize_t preadv(int, const struct iovec *, int, off_t);
extern ssize_t pwritev(int, const struct iovec *, int, off_t);
extern ssize_t copy_file_range(int, off_t *, int, off_t *, size_t,
                               unsigned int);
extern ssize_t sendfile(int, int, off_t *, size_t);
extern ssize_t splice(int, off_t *, int, off_t *, size_t, unsigned int);
extern ssize_t tee(int, int, size_t, unsigned int);
extern ssize_t vmsplice(int, const struct iovec *, size_t, unsigned int);
extern int fallocate(int, int, off_t, off_t);
extern int posix_fallocate(int, off_t, off_t);
extern int posix_fadvise(int, off_t, off_t, int);

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

static int same_bytes(const char *actual, const char *expected, size_t len)
{
    return memcmp(actual, expected, len) == 0;
}

int main(void)
{
    char source_name[] = "/tmp/crabc-m4-io-source-XXXXXX";
    char range_name[] = "/tmp/crabc-m4-io-range-XXXXXX";
    char send_name[] = "/tmp/crabc-m4-io-send-XXXXXX";
    char splice_name[] = "/tmp/crabc-m4-io-splice-XXXXXX";
    const char expected[] = "abcdeFGHI";
    char read_back[sizeof expected - 1];
    char range_back[sizeof expected - 1];
    char send_back[sizeof expected - 1];
    char splice_back[sizeof expected - 1];
    char tee_left[sizeof expected - 1];
    char tee_right[sizeof expected - 1];
    char vm_source[] = "vmsplice";
    char vm_back[sizeof vm_source];
    char first_left[] = "ab";
    char first_right[] = "cde";
    char second_left[] = "FG";
    char second_right[] = "HI";
    struct iovec first[] = {
        { first_left, sizeof first_left - 1 },
        { first_right, sizeof first_right - 1 },
    };
    struct iovec second[] = {
        { second_left, sizeof second_left - 1 },
        { second_right, sizeof second_right - 1 },
    };
    struct iovec read_vec[] = {
        { read_back, 4 },
        { read_back + 4, sizeof read_back - 4 },
    };
    struct iovec vm_vec[] = {
        { vm_source, sizeof vm_source - 1 },
    };
    int source = -1;
    int range = -1;
    int send = -1;
    int splice_file = -1;
    int first_pipe[2] = { -1, -1 };
    int second_pipe[2] = { -1, -1 };
    int vm_pipe[2] = { -1, -1 };
    off_t source_offset;
    off_t range_input;
    off_t range_output;
    off_t send_offset;

    source = mkstemp(source_name);
    range = mkstemp(range_name);
    send = mkstemp(send_name);
    splice_file = mkstemp(splice_name);
    CHECK(source >= 0 && range >= 0 && send >= 0 && splice_file >= 0,
          "mkstemp");

    CHECK(writev(source, first, 2) == 5, "writev");
    CHECK(pwritev(source, second, 2, 5) == 4, "pwritev");

    CHECK(preadv(source, read_vec, 2, 0) == (ssize_t)(sizeof expected - 1),
          "preadv");
    CHECK(same_bytes(read_back, expected, sizeof expected - 1), "preadv data");

    errno = 0;
    CHECK(posix_fadvise(source, 0, sizeof expected - 1, POSIX_FADV_SEQUENTIAL) == 0 &&
              errno == 0,
          "posix_fadvise");
    CHECK(fallocate(source, 0, 0, sizeof expected - 1) == 0, "fallocate");
    CHECK(posix_fallocate(range, 0, sizeof expected - 1) == 0,
          "posix_fallocate");

    range_input = 0;
    range_output = 0;
    CHECK(copy_file_range(source, &range_input, range, &range_output,
                          sizeof expected - 1, 0) ==
              (ssize_t)(sizeof expected - 1),
          "copy_file_range");
    CHECK(pread(range, range_back, sizeof range_back, 0) ==
              (ssize_t)sizeof range_back,
          "copy_file_range read");
    CHECK(same_bytes(range_back, expected, sizeof expected - 1),
          "copy_file_range data");

    send_offset = 0;
    CHECK(sendfile(send, source, &send_offset, sizeof expected - 1) ==
              (ssize_t)(sizeof expected - 1),
          "sendfile");
    CHECK(pread(send, send_back, sizeof send_back, 0) ==
              (ssize_t)sizeof send_back,
          "sendfile read");
    CHECK(same_bytes(send_back, expected, sizeof expected - 1),
          "sendfile data");

    CHECK(pipe(first_pipe) == 0 && pipe(second_pipe) == 0 && pipe(vm_pipe) == 0,
          "pipe");
    source_offset = 0;
    CHECK(splice(source, &source_offset, first_pipe[1], NULL,
                 sizeof expected - 1, 0) == (ssize_t)(sizeof expected - 1),
          "splice into pipe");
    CHECK(splice(first_pipe[0], NULL, splice_file, NULL,
                 sizeof expected - 1, 0) == (ssize_t)(sizeof expected - 1),
          "splice out of pipe");
    CHECK(pread(splice_file, splice_back, sizeof splice_back, 0) ==
              (ssize_t)sizeof splice_back,
          "splice read");
    CHECK(same_bytes(splice_back, expected, sizeof expected - 1),
          "splice data");

    source_offset = 0;
    CHECK(splice(source, &source_offset, first_pipe[1], NULL,
                 sizeof expected - 1, 0) == (ssize_t)(sizeof expected - 1),
          "splice for tee");
    CHECK(tee(first_pipe[0], second_pipe[1], sizeof expected - 1, 0) ==
              (ssize_t)(sizeof expected - 1),
          "tee");
    CHECK(read(first_pipe[0], tee_left, sizeof tee_left) ==
              (ssize_t)sizeof tee_left,
          "tee left read");
    CHECK(read(second_pipe[0], tee_right, sizeof tee_right) ==
              (ssize_t)sizeof tee_right,
          "tee right read");
    CHECK(same_bytes(tee_left, expected, sizeof expected - 1) &&
              same_bytes(tee_right, expected, sizeof expected - 1),
          "tee data");

    CHECK(vmsplice(vm_pipe[1], vm_vec, 1, 0) ==
              (ssize_t)(sizeof vm_source - 1),
          "vmsplice");
    CHECK(read(vm_pipe[0], vm_back, sizeof vm_source - 1) ==
              (ssize_t)(sizeof vm_source - 1),
          "vmsplice read");
    CHECK(same_bytes(vm_back, vm_source, sizeof vm_source - 1),
          "vmsplice data");

    puts("m4 io exports ok");
    close(source);
    close(range);
    close(send);
    close(splice_file);
    close(first_pipe[0]);
    close(first_pipe[1]);
    close(second_pipe[0]);
    close(second_pipe[1]);
    close(vm_pipe[0]);
    close(vm_pipe[1]);
    unlink(source_name);
    unlink(range_name);
    unlink(send_name);
    unlink(splice_name);
    return 0;

cleanup:
    if (source >= 0) close(source);
    if (range >= 0) close(range);
    if (send >= 0) close(send);
    if (splice_file >= 0) close(splice_file);
    if (first_pipe[0] >= 0) close(first_pipe[0]);
    if (first_pipe[1] >= 0) close(first_pipe[1]);
    if (second_pipe[0] >= 0) close(second_pipe[0]);
    if (second_pipe[1] >= 0) close(second_pipe[1]);
    if (vm_pipe[0] >= 0) close(vm_pipe[0]);
    if (vm_pipe[1] >= 0) close(vm_pipe[1]);
    unlink(source_name);
    unlink(range_name);
    unlink(send_name);
    unlink(splice_name);
    return 1;
}
