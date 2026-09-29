/* One static pathname/descriptor stream lifecycle, run unchanged with pinned
 * musl and the owned x86 runtime. Every update-stream direction change uses
 * successful positioning, so the observed bytes have defined C semantics.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(number, condition) do { if (!(condition)) return (number); } while (0)

static int closed_descriptor(int descriptor)
{
    errno = 0;
    return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
}

static int file_bytes(const char *path, const char *expected, size_t length)
{
    char bytes[32];
    int descriptor = open(path, O_RDONLY);
    if (descriptor < 0) return 0;
    ssize_t count = read(descriptor, bytes, sizeof bytes);
    int close_result = close(descriptor);
    return count == (ssize_t)length && close_result == 0 &&
        memcmp(bytes, expected, length) == 0;
}

int main(int argc, char **argv)
{
    char buffer[32], observed[8];
    fpos_t saved;
    FILE *stream, *reopened;
    int descriptor;

    CHECK(1, argc == 4);
    unlink(argv[1]);
    unlink(argv[2]);
    errno = 0;
    CHECK(2, fopen(argv[3], "r") == NULL && errno == ENOENT);

    stream = fopen(argv[1], "w+");
    CHECK(3, stream != NULL);
    descriptor = fileno(stream);
    CHECK(4, descriptor >= 0 && setvbuf(stream, buffer, _IOFBF, sizeof buffer) == 0);
    CHECK(5, fwrite("abcdef", 1, 6, stream) == 6 && ftello(stream) == 6);
    CHECK(6, fflush(stream) == 0 && lseek(descriptor, 0, SEEK_CUR) == 6);
    errno = 0;
    CHECK(7, fseeko(stream, -1, SEEK_SET) == -1 && errno == EINVAL && !ferror(stream));
    CHECK(8, fgetpos(stream, &saved) == 0 && fseeko(stream, 0, SEEK_SET) == 0);
    CHECK(9, fread(observed, 1, 2, stream) == 2 &&
        memcmp(observed, "ab", 2) == 0 && ftello(stream) == 2);
    CHECK(10, fseeko(stream, 0, SEEK_CUR) == 0 &&
        fwrite("Z", 1, 1, stream) == 1 && ftello(stream) == 3);
    CHECK(11, fflush(stream) == 0 && fsetpos(stream, &saved) == 0);
    CHECK(12, fseeko(stream, 0, SEEK_SET) == 0 &&
        fread(observed, 1, 6, stream) == 6 && memcmp(observed, "abZdef", 6) == 0);
    CHECK(13, fgetc(stream) == EOF && feof(stream) && !ferror(stream));
    rewind(stream);
    CHECK(14, !feof(stream) && !ferror(stream) && fgetc(stream) == 'a');
    CHECK(15, unlink(argv[1]) == 0);
    errno = 0;
    CHECK(16, fopen(argv[1], "r") == NULL && errno == ENOENT);
    CHECK(17, fseeko(stream, 0, SEEK_SET) == 0 && fgetc(stream) == 'a');
    CHECK(18, fclose(stream) == 0 && closed_descriptor(descriptor));

    descriptor = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(19, descriptor >= 0);
    errno = 0;
    CHECK(42, fdopen(descriptor, "q") == NULL && errno == EINVAL &&
        fcntl(descriptor, F_GETFD) >= 0);
    stream = fdopen(descriptor, "w+");
    CHECK(20, stream != NULL && fileno(stream) == descriptor);
    CHECK(21, setvbuf(stream, NULL, _IONBF, 0) == 0);
    CHECK(22, fwrite("one", 1, 3, stream) == 3 && fseeko(stream, 0, SEEK_SET) == 0);
    CHECK(23, fread(observed, 1, 3, stream) == 3 && memcmp(observed, "one", 3) == 0);
    CHECK(24, fclose(stream) == 0 && closed_descriptor(descriptor));
    CHECK(25, file_bytes(argv[1], "one", 3));

    stream = fopen(argv[1], "a+");
    CHECK(26, stream != NULL);
    CHECK(27, fseeko(stream, 0, SEEK_SET) == 0 && fwrite("!", 1, 1, stream) == 1);
    CHECK(28, fflush(stream) == 0 && fclose(stream) == 0);
    CHECK(29, file_bytes(argv[1], "one!", 4));

    stream = fopen(argv[1], "w+");
    CHECK(30, stream != NULL);
    descriptor = fileno(stream);
    CHECK(31, setvbuf(stream, buffer, _IOFBF, sizeof buffer) == 0);
    CHECK(32, fwrite("old", 1, 3, stream) == 3);
    reopened = freopen(argv[2], "w+", stream);
    CHECK(33, reopened == stream && fileno(stream) == descriptor);
    CHECK(34, file_bytes(argv[1], "old", 3));
    CHECK(35, fwrite("new", 1, 3, stream) == 3 && fflush(stream) == 0);
    CHECK(36, fseeko(stream, 0, SEEK_SET) == 0 &&
        fread(observed, 1, 3, stream) == 3 && memcmp(observed, "new", 3) == 0);
    reopened = freopen(NULL, "a+", stream);
    CHECK(43, reopened == stream && fileno(stream) == descriptor);
    CHECK(44, fseeko(stream, 0, SEEK_SET) == 0 && fputc('!', stream) == '!');
    CHECK(45, fflush(stream) == 0);
    CHECK(37, fclose(stream) == 0 && closed_descriptor(descriptor));
    CHECK(38, file_bytes(argv[2], "new!", 4));

    stream = fopen(argv[2], "r");
    CHECK(39, stream != NULL);
    descriptor = fileno(stream);
    errno = 0;
    reopened = freopen(argv[3], "r", stream);
    CHECK(40, reopened == NULL && errno == ENOENT && closed_descriptor(descriptor));
    CHECK(41, unlink(argv[1]) == 0 && unlink(argv[2]) == 0);
    return 0;
}
