#ifndef _FTW_H
#define _FTW_H

#include <sys/stat.h>

struct FTW { int base; int level; };

#define FTW_F 0
#define FTW_D 1
#define FTW_DNR 2
#define FTW_NS 3
#define FTW_SL 4
#define FTW_DP 5
#define FTW_SLN 6
#define FTW_PHYS 1
#define FTW_MOUNT 2
#define FTW_CHDIR 4
#define FTW_DEPTH 8

int ftw(const char *, int (*)(const char *, const struct stat *, int), int);
int nftw(const char *, int (*)(const char *, const struct stat *, int, struct FTW *), int, int);

#endif
