#ifndef _STRINGS_H
#define _STRINGS_H

#include <string.h>

int ffs(int);
int ffsl(long);
int ffsll(long long);
void bcopy(const void *, void *, size_t);
void bzero(void *, size_t);
char *index(const char *, int);
char *rindex(const char *, int);
int strcasecmp(const char *, const char *);
int strcasecmp_l(const char *, const char *, locale_t);
int strncasecmp(const char *, const char *, size_t);
int strncasecmp_l(const char *, const char *, size_t, locale_t);

#endif
