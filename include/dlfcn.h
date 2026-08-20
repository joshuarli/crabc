#ifndef _DLFCN_H
#define _DLFCN_H

#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_GLOBAL 0x100
#define RTLD_LOCAL 0

void *dlopen(const char *, int);
int dlclose(void *);
void *dlsym(void *restrict, const char *restrict);
char *dlerror(void);

#endif
