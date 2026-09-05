#include <stdio.h>
#ifdef INITIAL_EXEC
_Thread_local int failure_tls __attribute__((tls_model("initial-exec"))) = 19;
#else
_Thread_local int failure_tls = 19;
#endif
int *failure_address(void) { return &failure_tls; }
static void initialize(void) __attribute__((constructor));
static void initialize(void) { puts("FAIL: rejected object constructor executed"); }
