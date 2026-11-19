#if defined(__x86_64__) || defined(__aarch64__)
#warning redirecting incorrect #include <sys/errno.h> to <errno.h>
#include <errno.h>
#endif
