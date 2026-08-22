/* Direct pinned-Musl differential for the selected contended pthread route. */
#include <stdint.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/pthread_mutex_cond_ping_pong_contract.h"

int main(void)
{
    uint64_t observed = 0;

    if (pthread_mutex_cond_ping_pong_run(10000, &observed) != 0
            || observed != 20000)
        return 1;
    puts("pthread mutex condition ping-pong contract ok");
    return 0;
}
