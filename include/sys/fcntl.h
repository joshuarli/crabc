#if defined(__x86_64__)
#warning redirecting incorrect #include <sys/fcntl.h> to <fcntl.h>
#include <fcntl.h>
#else
#ifndef _CRABC_SYS_FCNTL_H
#define _CRABC_SYS_FCNTL_H

#include <fcntl.h>

#endif
#endif
