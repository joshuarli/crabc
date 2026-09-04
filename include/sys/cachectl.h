#if defined(__x86_64__)
#ifndef _SYS_CACHECTL_H
#define _SYS_CACHECTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define ICACHE (1<<0)
#define DCACHE (1<<1)
#define BCACHE (ICACHE|DCACHE)
#define CACHEABLE 0
#define UNCACHEABLE 1

int cachectl(void *, int, int);
int cacheflush(void *, int, int);
int _flush_cache(void *, int, int);

#ifdef __cplusplus
}
#endif

#endif
#else
#ifndef _CRABC_SYS_CACHECTL_H
#define _CRABC_SYS_CACHECTL_H

#define ICACHE (1 << 0)
#define DCACHE (1 << 1)
#define BCACHE (ICACHE | DCACHE)
#define CACHEABLE 0
#define UNCACHEABLE 1

#ifdef __cplusplus
extern "C" {
#endif

int cachectl(void *, int, int);
int cacheflush(void *, int, int);
int _flush_cache(void *, int, int);

#ifdef __cplusplus
}
#endif

#endif
#endif
