#define _GNU_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_file(const char *dir, const char *name) {
    char path[256];
    int fd;
    if (snprintf(path, sizeof path, "%s/%s", dir, name) < 0) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    return close(fd);
}

static int test_stream(const char *dir) {
    DIR *stream = opendir(dir);
    struct dirent *first;
    struct dirent *second;
    struct dirent *again;
    struct dirent entry;
    struct dirent *entry_result = NULL;
    char first_name[256];
    char second_name[256];
    long saved;
    int saw_dot = 0;
    int saw_dotdot = 0;
    int saw_a = 0;
    int saw_b = 0;

    if (!stream || dirfd(stream) < 0) return 1;
    first = readdir(stream);
    if (!first || first->d_reclen == 0) return 2;
    strcpy(first_name, first->d_name);
    saved = telldir(stream);
    second = readdir(stream);
    if (!second || saved < 0) return 3;
    strcpy(second_name, second->d_name);
    seekdir(stream, saved);
    again = readdir(stream);
    if (!again || strcmp(again->d_name, second_name) != 0) return 4;
    rewinddir(stream);
    again = readdir(stream);
    if (!again || strcmp(again->d_name, first_name) != 0) return 5;

    rewinddir(stream);
    while ((again = readdir(stream)) != NULL) {
        if (strcmp(again->d_name, ".") == 0) saw_dot = 1;
        if (strcmp(again->d_name, "..") == 0) saw_dotdot = 1;
        if (strcmp(again->d_name, "a") == 0) saw_a = 1;
        if (strcmp(again->d_name, "b") == 0) saw_b = 1;
    }
    if (!saw_dot || !saw_dotdot || !saw_a || !saw_b) return 6;

    rewinddir(stream);
    if (readdir_r(stream, &entry, &entry_result) != 0 || entry_result != &entry) return 7;
    if (strcmp(entry.d_name, first_name) != 0) return 8;
    if (closedir(stream) != 0) return 9;
    return 0;
}

static int test_fdopendir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *stream;
    if (fd < 0) return 1;
    stream = fdopendir(fd);
    if (!stream || dirfd(stream) != fd) return 2;
    if (closedir(stream) != 0) return 3;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 4;
    return 0;
}

static int test_directory_comparators(void) {
    struct dirent alpha;
    struct dirent beta;
    struct dirent version2;
    struct dirent version10;
    const struct dirent *left;
    const struct dirent *right;

    memset(&alpha, 0, sizeof alpha);
    memset(&beta, 0, sizeof beta);
    memset(&version2, 0, sizeof version2);
    memset(&version10, 0, sizeof version10);
    strcpy(alpha.d_name, "alpha");
    strcpy(beta.d_name, "beta");
    strcpy(version2.d_name, "file2");
    strcpy(version10.d_name, "file10");

    left = &alpha;
    right = &beta;
    if (alphasort(&left, &right) >= 0 || alphasort(&right, &left) <= 0) return 1;
    left = &version2;
    right = &version10;
    if (versionsort(&left, &right) >= 0 || versionsort(&right, &left) <= 0) return 2;
    return 0;
}

int main(void) {
    char dir[] = "/tmp/crabc-c-abi-dirs-XXXXXX";
    char path[256];
    int result;

    if (!mkdtemp(dir)) return 1;
    if (make_file(dir, "a") || make_file(dir, "b")) return 2;

    result = test_stream(dir);
    if (!result) result = test_fdopendir(dir);
    if (!result) result = test_directory_comparators();

    if (snprintf(path, sizeof path, "%s/a", dir) > 0) unlink(path);
    if (snprintf(path, sizeof path, "%s/b", dir) > 0) unlink(path);
    rmdir(dir);

    if (result) return result;
    puts("c-abi directory streams ok");
    return 0;
}
