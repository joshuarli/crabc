#if defined(__x86_64__)
#warning redirecting incorrect #include <sys/errno.h> to <errno.h>
#include <errno.h>
#else
#ifndef _CRABC_SYS_ERRNO_H
#define _CRABC_SYS_ERRNO_H

#include <errno.h>

#endif
#endif
