/*
 * Recycle more worker lifetimes than the fixed pthread slot table while
 * checking create/join publication and both static and pthread-key TLS.
 */
#include <pthread.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/pthread_create_join_tls_contract.h"

int main(void)
{
    pthread_key_t key;

    if (pthread_key_create(&key, NULL) != 0)
        return 1;
    for (unsigned int sequence = 0; sequence < 513; ++sequence) {
        const int status = pthread_create_join_tls_round_run(key, sequence);
        if (status != 0)
            return 10 + status;
    }
    if (pthread_key_delete(key) != 0)
        return 20;
    puts("pthread create/join tls contract ok");
    return 0;
}
