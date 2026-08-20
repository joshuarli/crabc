#ifndef _DIRENT_H
#define _DIRENT_H

#include <sys/types.h>

typedef struct __dirstream DIR;

struct dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

int alphasort(const struct dirent **, const struct dirent **);
int closedir(DIR *);
int dirfd(DIR *);
DIR *fdopendir(int);
DIR *opendir(const char *);
struct dirent *readdir(DIR *);
int readdir_r(DIR *restrict, struct dirent *restrict, struct dirent **restrict);
void rewinddir(DIR *);
int scandir(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **));
void seekdir(DIR *, long);
long telldir(DIR *);

#endif
