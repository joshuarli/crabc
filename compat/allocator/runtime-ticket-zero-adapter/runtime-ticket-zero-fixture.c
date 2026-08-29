/*
 * SPDX-License-Identifier: MIT
 *
 * One process-isolated C boundary regression for the Rust ticket-zero runtime
 * owner. It deliberately does not call crabc's malloc/free symbols: the
 * current production libc backend remains libmimalloc-sys.
 */
#include "crabc-mimalloc-runtime-ticket-zero-test.h"

#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#define DEFAULT_WORKER_CYCLES 3U
#define MAX_WORKER_CYCLES 1024U
#define DEFAULT_STRESS_SEED UINT64_C(0x9e3779b97f4a7c15)

/*
 * The normal fixture remains a short boundary regression. The allocator
 * harness may request a larger, still-bounded lifecycle soak by repeating the
 * existing pointer-private worker witnesses in this same fresh process. A
 * seed changes only the order in which each cycle visits every witness; it
 * does not create a concurrent allocation entry point or widen the Rust C ABI.
 */
static int parse_worker_options(int argc, char **argv, size_t *cycles,
                                uint64_t *stress_seed)
{
    int cycle_seen = 0;
    int seed_seen = 0;
    int index;

    *cycles = DEFAULT_WORKER_CYCLES;
    *stress_seed = DEFAULT_STRESS_SEED;
    if ((argc - 1) % 2 != 0)
        return -1;

    for (index = 1; index < argc; index += 2) {
        const char *value = argv[index + 1];
        char *end;

        if (strcmp(argv[index], "--worker-cycles") == 0) {
            unsigned long parsed;

            if (cycle_seen || value[0] < '1' || value[0] > '9')
                return -1;
            errno = 0;
            parsed = strtoul(value, &end, 10);
            if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
                parsed > MAX_WORKER_CYCLES || (size_t)parsed != parsed)
                return -1;
            *cycles = (size_t)parsed;
            cycle_seen = 1;
            continue;
        }

        if (strcmp(argv[index], "--stress-seed") == 0) {
            unsigned long long parsed;

            /* strtoull accepts a leading sign, but the schedule contract is
             * an unsigned 64-bit seed rather than a signed spelling of one. */
            if (seed_seen || value[0] == '\0' || value[0] == '-' ||
                value[0] == '+')
                return -1;
            errno = 0;
            parsed = strtoull(value, &end, 0);
            if (errno != 0 || end == value || *end != '\0' ||
                (uint64_t)parsed != parsed)
                return -1;
            *stress_seed = (uint64_t)parsed;
            seed_seen = 1;
            continue;
        }

        return -1;
    }

    return 0;
}

static int check_pattern(const unsigned char *block, size_t size)
{
    size_t index;

    for (index = 0; index < size; index++) {
        if (block[index] != (unsigned char)(index + 3))
            return 0;
    }
    return 1;
}

static void *run_worker_roundtrip(void *argument)
{
    const size_t size = (size_t)(uintptr_t)argument;

    errno = EAGAIN;
    if (crabc_ticket_zero_test_worker_roundtrip(size) != 0 || errno != EAGAIN)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *run_worker_mixed_roundtrip(void *argument)
{
    (void)argument;

    errno = EAGAIN;
    if (crabc_ticket_zero_test_worker_mixed_roundtrip() != 0 || errno != EAGAIN)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *run_worker_remote_free_roundtrip(void *argument)
{
    (void)argument;

    errno = EAGAIN;
    if (crabc_ticket_zero_test_worker_remote_free_roundtrip() != 0 || errno != EAGAIN)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *run_worker_owner_exit_roundtrip(void *argument)
{
    (void)argument;

    errno = EAGAIN;
    if (crabc_ticket_zero_test_worker_owner_exit_roundtrip() != 0 || errno != EAGAIN)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *run_worker_owner_exit_reclaim_roundtrip(void *argument)
{
    (void)argument;

    errno = EAGAIN;
    if (crabc_ticket_zero_test_worker_owner_exit_reclaim_roundtrip() != 0 || errno != EAGAIN)
        return (void *)(uintptr_t)1;
    return NULL;
}

typedef void *(*worker_start)(void *);

/*
 * This is a deterministic schedule generator for the evidence fixture, not
 * allocator randomness. Each cycle still runs every currently supported
 * pointer-private worker route exactly once; the seed only varies the order
 * in which independent A/B/C lifecycles meet the retained ticket-zero owner.
 */
static uint64_t next_worker_schedule(uint64_t *state)
{
    *state = *state * UINT64_C(6364136223846793005) +
             UINT64_C(1442695040888963407);
    return *state;
}

static int run_scheduled_worker(worker_start start)
{
    pthread_t worker;
    void *worker_result;

    if (pthread_create(&worker, NULL, start, NULL) != 0)
        return -1;
    if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL)
        return -1;
    return 0;
}

static int run_seeded_worker_cycle(uint64_t *stress_seed)
{
    worker_start routes[] = {
        run_worker_mixed_roundtrip,
        run_worker_remote_free_roundtrip,
        run_worker_owner_exit_roundtrip,
        run_worker_owner_exit_reclaim_roundtrip,
    };
    size_t index;

    for (index = sizeof(routes) / sizeof(routes[0]); index > 1; index--) {
        const size_t other = (size_t)(next_worker_schedule(stress_seed) % index);
        worker_start temporary = routes[index - 1];

        routes[index - 1] = routes[other];
        routes[other] = temporary;
    }
    for (index = 0; index < sizeof(routes) / sizeof(routes[0]); index++) {
        if (run_scheduled_worker(routes[index]) != 0)
            return (int)(index + 1);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const size_t first_size = 37;
    const size_t grown_size = 173;
    unsigned char *block;
    unsigned char *zeroed;
    pthread_t worker;
    void *worker_result;
    size_t index;
    size_t worker_cycles;
    uint64_t stress_seed;

    if (parse_worker_options(argc, argv, &worker_cycles, &stress_seed) != 0)
        return 19;

    errno = E2BIG;
    if (crabc_ticket_zero_test_init(getauxval(AT_PAGESZ)) != 0)
        return 1;
    if (errno != E2BIG)
        return 2;

    errno = EINTR;
    block = crabc_ticket_zero_test_malloc(first_size);
    if (block == NULL || errno != EINTR)
        return 3;
    for (index = 0; index < first_size; index++)
        block[index] = (unsigned char)(index + 3);

    errno = EOVERFLOW;
    block = crabc_ticket_zero_test_realloc(block, grown_size);
    if (block == NULL || errno != EOVERFLOW || !check_pattern(block, first_size))
        return 4;

    errno = ERANGE;
    zeroed = crabc_ticket_zero_test_zalloc(first_size);
    if (zeroed == NULL || errno != ERANGE)
        return 5;
    for (index = 0; index < first_size; index++) {
        if (zeroed[index] != 0)
            return 6;
    }

    errno = EDOM;
    crabc_ticket_zero_test_free(zeroed);
    if (errno != EDOM)
        return 7;
    errno = EILSEQ;
    crabc_ticket_zero_test_free(block);
    if (errno != EILSEQ)
        return 8;

    if (pthread_create(&worker, NULL, run_worker_roundtrip, (void *)(uintptr_t)grown_size) != 0)
        return 9;
    if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL)
        return 10;

    for (index = 0; index < worker_cycles; index++) {
        if (run_seeded_worker_cycle(&stress_seed) != 0)
            return 11;
    }

    errno = ENOSPC;
    block = crabc_ticket_zero_test_malloc(grown_size);
    if (block == NULL || errno != ENOSPC)
        return 19;
    memset(block, 0x4d, grown_size);

    errno = EBUSY;
    crabc_ticket_zero_test_free(block);
    if (errno != EBUSY)
        return 20;

    fputs("runtime ticket-zero allocator ok\n", stdout);
    return 0;
}
