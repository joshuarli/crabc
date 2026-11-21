#if defined(__x86_64__) || defined(__aarch64__)
#warning redirecting incorrect #include <sys/signal.h> to <signal.h>
#include <signal.h>
#endif
