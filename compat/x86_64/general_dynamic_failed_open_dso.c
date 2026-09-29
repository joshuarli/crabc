#if defined(FAILED_OPEN_TLS)
#include <unistd.h>
__thread int failed_open_tls_value = 37;
int *failed_open_tls_address(void) { return &failed_open_tls_value; }
__attribute__((constructor)) static void failed_open_tls_constructor(void) {
    (void)write(1, "T\n", 2);
}
#elif defined(FAILED_OPEN_LATE)
#include <unistd.h>
int failed_open_late_value = 5;
int failed_open_late_anchor(void) { return 1; }
#ifdef FAILED_OPEN_MISSING_SYMBOL
pid_t (*failed_open_late_import)(void) = getpid;
#endif
#elif defined(FAILED_OPEN_ROOT)
extern int *failed_open_tls_address(void);
extern int failed_open_late_value;
int failed_open_root_value(void) {
    return *failed_open_tls_address() + failed_open_late_value;
}
#else
#error select a failed-open DSO role
#endif
