#include <stdlib.h>

/* This application's strong definition must not run under the loader's
 * graph lock. The external observer still requires every real r_brk event. */
void _dl_debug_state(void) { _Exit(61); }
