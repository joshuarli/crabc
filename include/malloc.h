#ifndef _CRABC_MALLOC_H
#define _CRABC_MALLOC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void *valloc(size_t);
void *memalign(size_t, size_t);
size_t malloc_usable_size(void *);

#ifdef __cplusplus
}
#endif

#endif
