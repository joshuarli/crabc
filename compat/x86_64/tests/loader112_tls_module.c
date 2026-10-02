#include <stdint.h>

#ifndef TLS_SEED
#error TLS_SEED must identify the initialized module image
#endif

static _Thread_local int value = TLS_SEED;
static _Thread_local unsigned char zero[257] __attribute__((aligned(4096)));
static unsigned constructed, destroyed;

__attribute__((constructor)) static void initialize(void)
{
    constructed += value == TLS_SEED && zero[0] == 0 && zero[256] == 0;
}

__attribute__((destructor)) static void finalize(void) { ++destroyed; }

int *loader112_cell(void) { return &value; }
unsigned char *loader112_zero(void) { return zero; }
int loader112_ready(void)
{
    return constructed == 1 && destroyed == 0 && ((uintptr_t)zero & 4095) == 0;
}
