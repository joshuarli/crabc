/* Physical pathname and adopted-descriptor stream lifetime observations.
 * Each invocation gets private paths and runs from the same object against
 * both runtimes. Descriptor numbers and path spelling are intentionally absent
 * from output because only their relationships and effects are contractual.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(step, condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d\n", scenario, (step)); return (step); \
} } while (0)

static const char *scenario;

static int closed_descriptor(int fd)
{
    errno = 0;
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

static int file_content(const char *path, const char *expected, size_t length)
{
    char bytes[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t count = read(fd, bytes, sizeof bytes);
    int result = close(fd);
    return count == (ssize_t)length && result == 0 &&
        memcmp(bytes, expected, length) == 0;
}

static int buffered_reopen(const char *first, const char *second)
{
    char buffer[16], observed[8];
    FILE *stream = fopen(first, "w+");
    struct stat before;
    int fd;
    CHECK(10, stream != NULL);
    fd = fileno(stream);
    CHECK(11, fd >= 0 && setvbuf(stream, buffer, _IOFBF, sizeof buffer) == 0);
    CHECK(12, fwrite("first", 1, 5, stream) == 5 && ftello(stream) == 5);
    CHECK(13, fstat(fd, &before) == 0);
    printf("buffered initial logical=5 physical=%lld\n", (long long)before.st_size);
    CHECK(14, freopen(second, "w+", stream) == stream);
    CHECK(15, fileno(stream) == fd && ftello(stream) == 0 &&
        !feof(stream) && !ferror(stream));
    CHECK(16, file_content(first, "first", 5));
    CHECK(17, fwrite("next", 1, 4, stream) == 4 && ftello(stream) == 4);
    CHECK(18, fflush(stream) == 0 && fseeko(stream, 0, SEEK_SET) == 0);
    CHECK(19, fread(observed, 1, 4, stream) == 4 &&
        memcmp(observed, "next", 4) == 0 && ftello(stream) == 4);
    CHECK(20, fclose(stream) == 0 && closed_descriptor(fd));
    CHECK(21, file_content(second, "next", 4));
    puts("buffered reopen identity=kept old=first new=next close=closed");
    return 0;
}

static int adopted_position(const char *path)
{
    char buffer[16], observed[8];
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    FILE *stream;
    struct stat before;
    CHECK(30, fd >= 0);
    errno = 0;
    CHECK(31, fdopen(fd, "?") == NULL && errno == EINVAL &&
        fcntl(fd, F_GETFD) >= 0);
    stream = fdopen(fd, "w+");
    CHECK(32, stream != NULL && fileno(stream) == fd);
    CHECK(33, setvbuf(stream, buffer, _IOFBF, sizeof buffer) == 0);
    CHECK(34, fwrite("abcdef", 1, 6, stream) == 6 && ftello(stream) == 6);
    CHECK(35, fstat(fd, &before) == 0);
    printf("adopted initial logical=6 physical=%lld\n", (long long)before.st_size);
    CHECK(36, fflush(stream) == 0 && lseek(fd, 0, SEEK_CUR) == 6);
    CHECK(37, fseeko(stream, 0, SEEK_SET) == 0 &&
        fread(observed, 1, 2, stream) == 2 &&
        memcmp(observed, "ab", 2) == 0 && ftello(stream) == 2);
    CHECK(38, fseeko(stream, 1, SEEK_CUR) == 0 && fgetc(stream) == 'd' &&
        ftello(stream) == 4);
    CHECK(39, fclose(stream) == 0 && closed_descriptor(fd));
    CHECK(40, file_content(path, "abcdef", 6));
    puts("adopted position=4 content=abcdef close=closed");
    return 0;
}

static int null_append(const char *path)
{
    FILE *stream = fopen(path, "w+");
    int fd;
    CHECK(50, stream != NULL);
    fd = fileno(stream);
    CHECK(51, fwrite("base", 1, 4, stream) == 4 && fflush(stream) == 0);
    CHECK(52, freopen(NULL, "a+", stream) == stream && fileno(stream) == fd);
    CHECK(53, fseeko(stream, 0, SEEK_SET) == 0 &&
        fwrite("!", 1, 1, stream) == 1 && fflush(stream) == 0);
    CHECK(54, fclose(stream) == 0 && closed_descriptor(fd));
    CHECK(55, file_content(path, "base!", 5));
    puts("null append identity=kept content=base! close=closed");
    return 0;
}

static int failed_reopen(const char *path, const char *missing)
{
    FILE *stream = fopen(path, "w+");
    int fd;
    CHECK(60, stream != NULL);
    CHECK(61, fwrite("held", 1, 4, stream) == 4 && fflush(stream) == 0);
    fd = fileno(stream);
    CHECK(62, fseeko(stream, 0, SEEK_SET) == 0 && fgetc(stream) == 'h');
    errno = 0;
    CHECK(63, freopen(missing, "r", stream) == NULL && errno == ENOENT);
    CHECK(64, closed_descriptor(fd) && file_content(path, "held", 4));
    puts("failed reopen errno=ENOENT old=closed content=held");
    return 0;
}

static int adopted_read_error(const char *path)
{
    FILE *stream;
    int fd;
    CHECK(70, mkdir(path, 0700) == 0);
    fd = open(path, O_RDONLY | O_DIRECTORY);
    CHECK(71, fd >= 0);
    stream = fdopen(fd, "r");
    CHECK(72, stream != NULL && fileno(stream) == fd);
    errno = 0;
    CHECK(73, fgetc(stream) == EOF && errno == EISDIR &&
        ferror(stream) && !feof(stream));
    puts("adopted read error=EISDIR indicator=error eof=clear");
    clearerr(stream);
    CHECK(74, !ferror(stream) && !feof(stream));
    CHECK(75, fclose(stream) == 0 && closed_descriptor(fd));
    CHECK(76, rmdir(path) == 0);
    puts("adopted clearerr=clear close=closed");
    return 0;
}

int main(int argc, char **argv)
{
    int result;
    if (argc != 4) return 2;
    scenario = argv[1];
    if (unlink(argv[2]) != 0 && errno != ENOENT) return 3;
    if (unlink(argv[3]) != 0 && errno != ENOENT) return 4;
    if (strcmp(scenario, "buffered-reopen") == 0)
        result = buffered_reopen(argv[2], argv[3]);
    else if (strcmp(scenario, "adopted-position") == 0)
        result = adopted_position(argv[2]);
    else if (strcmp(scenario, "null-append") == 0)
        result = null_append(argv[2]);
    else if (strcmp(scenario, "failed-reopen") == 0)
        result = failed_reopen(argv[2], argv[3]);
    else if (strcmp(scenario, "adopted-read-error") == 0)
        result = adopted_read_error(argv[2]);
    else return 5;
    if (unlink(argv[2]) != 0 && errno != ENOENT && result == 0) result = 6;
    if (unlink(argv[3]) != 0 && errno != ENOENT && result == 0) result = 7;
    return result;
}
