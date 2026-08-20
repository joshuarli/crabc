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

#endif
