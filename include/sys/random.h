#ifndef _CRABC_SYS_RANDOM_H
#define _CRABC_SYS_RANDOM_H

#include <stddef.h>
#include <sys/types.h>

#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM 0x0002
#define GRND_INSECURE 0x0004

#ifdef __cplusplus
extern "C" {
#endif

ssize_t getrandom(void *, size_t, unsigned);

#ifdef __cplusplus
}
#endif
#endif
