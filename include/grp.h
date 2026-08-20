#ifndef _GRP_H
#define _GRP_H

#include <sys/types.h>

struct group {
    char *gr_name;
    char *gr_passwd;
    gid_t gr_gid;
    char **gr_mem;
};

void endgrent(void);
struct group *getgrent(void);
struct group *getgrgid(gid_t);
int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
struct group *getgrnam(const char *);
int getgrnam_r(const char *, struct group *, char *, size_t, struct group **);
void setgrent(void);
int setgroups(size_t, const gid_t []);
#ifdef _GNU_SOURCE
#include <stdio.h>
struct group *fgetgrent(FILE *);
int putgrent(const struct group *, FILE *);
int getgrouplist(const char *, gid_t, gid_t *, int *);
int initgroups(const char *, gid_t);
#elif defined(_BSD_SOURCE)
int getgrouplist(const char *, gid_t, gid_t *, int *);
int initgroups(const char *, gid_t);
#endif

#endif
