/* Direct pinned-Musl differential for growth of existing-thread dynamic TLS. */
#include <stdint.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/tls_growth_contract.h"

int main(int argc, char **argv)
{
    uint64_t observed = 0;
    int status;

    if (argc != 2)
        return 1;
    status = tls_growth_run(argv[1], TLS_GROWTH_MAX_MODULES, &observed);
    if (status != 0 || observed != TLS_GROWTH_MAX_MODULES) {
        fprintf(stderr, "dynamic TLS growth status=%d observed=%llu\n", status,
            (unsigned long long)observed);
        return 2;
    }
    puts("dynamic TLS growth contract ok");
    return 0;
}
