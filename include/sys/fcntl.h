#if defined(__x86_64__) || defined(__aarch64__)
#warning redirecting incorrect #include <sys/fcntl.h> to <fcntl.h>
#include <fcntl.h>
#endif
