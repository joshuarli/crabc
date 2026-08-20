#ifndef _GLOB_H
#define _GLOB_H

#include <stddef.h>

typedef struct {
    size_t gl_pathc;
    char **gl_pathv;
    size_t gl_offs;
    int __dummy1;
    void *__dummy2;
    void *__dummy3;
    void *__dummy4;
    void *__dummy5;
} glob_t;

#define GLOB_ERR 0x01
#define GLOB_MARK 0x02
#define GLOB_NOSORT 0x04
#define GLOB_DOOFFS 0x08
#define GLOB_NOCHECK 0x10
#define GLOB_APPEND 0x20
#define GLOB_NOESCAPE 0x40
#define GLOB_NOSPACE 1
#define GLOB_ABORTED 2
#define GLOB_NOMATCH 3

int glob(const char *restrict, int, int (*)(const char *, int), glob_t *restrict);
void globfree(glob_t *);

#endif
