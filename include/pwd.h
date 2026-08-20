#ifndef _PWD_H
#define _PWD_H

#include <features.h>
#include <sys/types.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void endpwent(void);
struct passwd *getpwent(void);
#endif
struct passwd *getpwnam(const char *);
int getpwnam_r(const char *, struct passwd *, char *, size_t, struct passwd **);
struct passwd *getpwuid(uid_t);
int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void setpwent(void);
#endif
#ifdef _GNU_SOURCE
#include <stdio.h>
struct passwd *fgetpwent(FILE *);
int putpwent(const struct passwd *, FILE *);
#endif

#endif
