#include <stdint.h>

#ifndef TLS_SEED
#error TLS_SEED must identify the initialized plugin image
#endif

_Thread_local unsigned tls_value = TLS_SEED;
static _Thread_local unsigned char zero[113] __attribute__((aligned(4096)));
static unsigned constructed;
static unsigned destroyed;

__attribute__((constructor)) static void initialize(void)
{
    constructed += tls_value == TLS_SEED && zero[0] == 0 && zero[112] == 0;
}

__attribute__((destructor)) static void finalize(void) { ++destroyed; }

int tls_ready(void)
{
    return constructed == 1 && destroyed == 0 && ((uintptr_t)zero & 4095) == 0
        && zero[0] == 0 && zero[112] == 0;
}

unsigned tls_get(void) { return tls_value; }
void tls_set(unsigned next) { tls_value = next; }
unsigned *tls_address(void) { return &tls_value; }
