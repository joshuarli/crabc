/* The identical PIC object is linked by the owned and musl DSO drivers.
 * Each load supplies a fresh relocated template and TBSS to old/new workers. */
#ifndef WORKER_TLS_GENERATION
#error "select one explicit worker TLS generation"
#endif
static _Thread_local int initialized = 300 + WORKER_TLS_GENERATION;
static _Thread_local unsigned char zero[257];
int *prepared_worker_initialized(void) { return &initialized; }
unsigned char *prepared_worker_zero(void) { return zero; }
