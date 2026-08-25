#ifndef _DLFCN_H
#define _DLFCN_H

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_NOLOAD 4
#define RTLD_NODELETE 4096
#define RTLD_GLOBAL 0x100
#define RTLD_LOCAL 0
#define RTLD_NEXT ((void *)-1)
#define RTLD_DEFAULT ((void *)0)

#define RTLD_DI_LINKMAP 2

void *dlopen(const char *, int);
int dlclose(void *);
void *dlsym(void *__restrict, const char *__restrict);
char *dlerror(void);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;

int dladdr(const void *, Dl_info *);
int dlinfo(void *, int, void *);
#endif

#ifdef __cplusplus
}
#endif

#endif
