#include <stdint.h>

#ifndef TLS_SEED
#error TLS_SEED must identify the initialized plugin image
#endif

static _Thread_local unsigned value = TLS_SEED;
static _Thread_local unsigned char zero[113] __attribute__((aligned(4096)));
static unsigned constructed;

__attribute__((constructor)) static void initialize(void)
{
    constructed = value == TLS_SEED && zero[0] == 0 && zero[112] == 0;
}

int tls_ready(void)
{
    return constructed && ((uintptr_t)zero & 4095) == 0
        && zero[0] == 0 && zero[112] == 0;
}

unsigned tls_get(void) { return value; }
void tls_set(unsigned next) { value = next; }
