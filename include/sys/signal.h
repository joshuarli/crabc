#if defined(__x86_64__)
#warning redirecting incorrect #include <sys/signal.h> to <signal.h>
#include <signal.h>
#else
#ifndef _CRABC_SYS_SIGNAL_H
#define _CRABC_SYS_SIGNAL_H

#include <signal.h>

#endif
#endif
