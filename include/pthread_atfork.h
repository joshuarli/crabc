#ifndef _PTHREAD_ATFORK_H
#define _PTHREAD_ATFORK_H

#ifdef __cplusplus
extern "C" {
#endif

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void));

#ifdef __cplusplus
}
#endif

#endif
