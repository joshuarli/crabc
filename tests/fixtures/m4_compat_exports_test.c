#define _GNU_SOURCE 1

#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int __xstat(int, const char *, struct stat *);
extern int __lxstat(int, const char *, struct stat *);
extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);
extern int __xmknod(int, const char *, mode_t, dev_t);
extern int __xmknodat(int, int, const char *, mode_t, dev_t);
extern char *__xpg_basename(char *);
extern int __xpg_strerror_r(int, char *, size_t);
extern long __strtol_internal(const char *, char **, int, int);
extern unsigned long __strtoul_internal(const char *, char **, int, int);
extern long long __strtoll_internal(const char *, char **, int, int);
extern unsigned long long __strtoull_internal(const char *, char **, int, int);
extern long __strtoimax_internal(const char *, char **, int, int);
extern unsigned long __strtoumax_internal(const char *, char **, int, int);

int main(void) {
    char path[] = "/tmp/crabc-m4-compat-XXXXXX";
    char node[256];
    char base[] = "/alpha/beta";
    char error[32];
    char *end;
    struct stat st;
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    if (__xstat(0, path, &st) || __lxstat(0, path, &st)) return 2;
    if (__fxstat(0, fd, &st) || __fxstatat(0, AT_FDCWD, path, &st, 0)) return 3;
    if (snprintf(node, sizeof node, "%s.node", path) < 0) return 4;
    if (__xmknod(0, node, S_IFIFO | 0600, 0) || unlink(node)) return 5;
    if (__xmknodat(0, AT_FDCWD, node, S_IFIFO | 0600, 0) || unlink(node)) return 6;
    if (strcmp(__xpg_basename(base), "beta")) return 7;
    if (__xpg_strerror_r(2, error, sizeof error) || strcmp(error, strerror(2))) return 8;
    if (__strtol_internal("-12x", &end, 10, 0) != -12 || *end != 'x') return 9;
    if (__strtoul_internal("ff", &end, 16, 0) != 255 || *end) return 10;
    if (__strtoll_internal("-42", &end, 10, 0) != -42 || *end) return 11;
    if (__strtoull_internal("77", &end, 8, 0) != 63 || *end) return 12;
    if (__strtoimax_internal("123", &end, 10, 0) != 123 || *end) return 13;
    if (__strtoumax_internal("100", &end, 10, 0) != 100 || *end) return 14;
    close(fd);
    unlink(path);
    puts("m4 compat exports ok");
    return 0;
}
