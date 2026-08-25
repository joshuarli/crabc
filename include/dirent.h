#ifndef _DIRENT_H
#define _DIRENT_H

#include <features.h>
#include <sys/types.h>

typedef struct __dirstream DIR;

struct dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

typedef unsigned short reclen_t;

struct posix_dent {
    ino_t d_ino;
    off_t d_off;
    reclen_t d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define IFTODT(mode) (((mode) >> 12) & 017)
#define DTTOIF(type) ((type) << 12)
#endif

int alphasort(const struct dirent **, const struct dirent **);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int versionsort(const struct dirent **, const struct dirent **);
#endif
int closedir(DIR *);
int dirfd(DIR *);
DIR *fdopendir(int);
DIR *opendir(const char *);
struct dirent *readdir(DIR *);
int readdir_r(DIR *__restrict, struct dirent *__restrict, struct dirent **__restrict);
int scandir(const char *, struct dirent ***, int (*)(const struct dirent *),
    int (*)(const struct dirent **, const struct dirent **));
void rewinddir(DIR *);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void seekdir(DIR *, long);
long telldir(DIR *);
#endif
ssize_t posix_getdents(int, void *, size_t, int);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getdents(int, struct dirent *, size_t);
#endif

#endif
