#ifndef _CRABC_ALLOCA_H
#define _CRABC_ALLOCA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *alloca(size_t);

#ifdef __cplusplus
}
#endif

#define alloca __builtin_alloca

#endif
