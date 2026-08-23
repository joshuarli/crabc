#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int check_file(const char *path, const char *expected, size_t length)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    char bytes[8] = {0};
    ssize_t count = read(fd, bytes, sizeof bytes);
    close(fd);
    return count == (ssize_t)length && memcmp(bytes, expected, length) == 0;
}

int main(void)
{
    char path[96];
    snprintf(path, sizeof path, "/tmp/crabc-compat-fclose-%ld", (long)getpid());
    unlink(path);

    char memory[16] = {0};
    FILE *memory_stream = fmemopen(memory, sizeof memory, "w+");
    if (!memory_stream) return 1;
    FILE *reopened = freopen(path, "w", memory_stream);
    if (!reopened) return 2;
    if (fputs("FILE", reopened) < 0) return 3;
    if (fclose(reopened) != 0) return 4;
    if (!check_file(path, "FILE", 4)) return 5;

    if (freopen(path, "w", stdout) != stdout) return 6;
    if (fputs("cf", stdout) < 0) return 7;
    if (fclose(stdout) != 0) return 8;
    int passed = check_file(path, "cf", 2);
    unlink(path);
    return passed ? 0 : 9;
}
