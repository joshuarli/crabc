#if defined(__x86_64__)
#warning redirecting incorrect #include <wait.h> to <sys/wait.h>
#include <sys/wait.h>
#else
#ifndef _CRABC_WAIT_H
#define _CRABC_WAIT_H

#include <sys/wait.h>

#endif
#endif
