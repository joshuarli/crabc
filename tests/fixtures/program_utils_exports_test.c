#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *get_current_dir_name(void);
extern int getdtablesize(void);
extern char *secure_getenv(const char *);
extern int mkostemp(char *, int);
extern int mkostemps(char *, int, int);
extern int mkstemps(char *, int);
extern void *memalign(size_t, size_t);
extern void *valloc(size_t);
extern size_t malloc_usable_size(void *);
extern char *getpass(const char *);

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    char cwd[4096];
    char *dynamic_cwd;
    char *canonical;
    char link_name[] = "/tmp/crabc-c-abi-program-link-XXXXXX";
    char target_name[] = "/tmp/crabc-c-abi-program-target-XXXXXX";
    char ostemp[] = "/tmp/crabc-c-abi-program-XXXXXX";
    char stemps[] = "/tmp/crabc-c-abi-program-XXXXXX.suffix";
    char ostemps[] = "/tmp/crabc-c-abi-program-XXXXXX.tail";
    char options[] = "alpha=one,beta,gamma=three";
    char *cursor = options;
    char *value = NULL;
    char *keys[] = { "alpha", "beta", "gamma", NULL };
    unsigned char source[] = { 1, 2, 3, 4, 5 };
    unsigned char swapped[5] = { 0 };
    FILE *stream;
    void *aligned;
    void *page_aligned;
    int fd;

    CHECK(ctermid(NULL) && strcmp(ctermid(NULL), "/dev/tty") == 0, "ctermid");
    CHECK(getcwd(cwd, sizeof cwd) != NULL, "getcwd");
    dynamic_cwd = get_current_dir_name();
    CHECK(dynamic_cwd != NULL && strcmp(dynamic_cwd, cwd) == 0, "current dir");
    free(dynamic_cwd);
    CHECK(getdtablesize() > 0, "getdtablesize");

    CHECK(setenv("CRABC_PROGRAM_UTILS_SECURE_ENV", "visible", 1) == 0, "setenv");
    CHECK(secure_getenv("CRABC_PROGRAM_UTILS_SECURE_ENV") != NULL &&
              strcmp(secure_getenv("CRABC_PROGRAM_UTILS_SECURE_ENV"), "visible") == 0,
          "secure getenv");

    CHECK(getsubopt(&cursor, keys, &value) == 0 && value && strcmp(value, "one") == 0,
          "getsubopt alpha");
    CHECK(getsubopt(&cursor, keys, &value) == 1 && value == NULL, "getsubopt beta");
    CHECK(getsubopt(&cursor, keys, &value) == 2 && value && strcmp(value, "three") == 0,
          "getsubopt gamma");

    fd = mkstemp(target_name);
    CHECK(fd >= 0, "mkstemp target");
    close(fd);
    CHECK(symlink(target_name, link_name) == 0, "symlink");
    canonical = realpath(link_name, NULL);
    if (!(canonical != NULL && strcmp(canonical, target_name) == 0)) {
        printf("realpath errno=%d got=%s want=%s\\n", errno,
               canonical ? canonical : "(null)", target_name);
        return 1;
    }
    free(canonical);

    fd = mkostemp(ostemp, O_CLOEXEC);
    CHECK(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC), "mkostemp");
    close(fd);
    fd = mkstemps(stemps, 7);
    CHECK(fd >= 0 && strcmp(stemps + strlen(stemps) - 7, ".suffix") == 0, "mkstemps");
    close(fd);
    fd = mkostemps(ostemps, 5, O_CLOEXEC);
    CHECK(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) &&
              strcmp(ostemps + strlen(ostemps) - 5, ".tail") == 0,
          "mkostemps");
    close(fd);

    aligned = memalign(64, 19);
    CHECK(aligned != NULL && ((uintptr_t)aligned % 64) == 0 &&
              // mimalloc owns allocation size classes; this legacy query is
              // only required to report space the caller may use.
              malloc_usable_size(aligned) >= 19, "memalign");
    free(aligned);
    page_aligned = valloc(7);
    CHECK(page_aligned != NULL && ((uintptr_t)page_aligned % 4096) == 0, "valloc");
    free(page_aligned);

    swab(source, swapped, sizeof source);
    CHECK(swapped[0] == 2 && swapped[1] == 1 && swapped[2] == 4 &&
              swapped[3] == 3 && swapped[4] == 0, "swab");
    stream = tmpfile();
    CHECK(stream != NULL && putw(0x12345678, stream) == 0, "putw");
    rewind(stream);
    CHECK(getw(stream) == 0x12345678, "getw");
    fclose(stream);

    puts("c-abi program utils ok");
    unlink(link_name);
    unlink(target_name);
    unlink(ostemp);
    unlink(stemps);
    unlink(ostemps);
    return 0;
}
