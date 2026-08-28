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
#include <string.h>
#include <sys/auxv.h>

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

int main(void)
{
    const size_t first_size = 37;
    const size_t grown_size = 173;
    unsigned char *block;
    unsigned char *zeroed;
    pthread_t worker;
    void *worker_result;
    size_t index;

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

    errno = ENOSPC;
    block = crabc_ticket_zero_test_malloc(grown_size);
    if (block == NULL || errno != ENOSPC)
        return 11;
    memset(block, 0x4d, grown_size);

    errno = EBUSY;
    crabc_ticket_zero_test_free(block);
    if (errno != EBUSY)
        return 12;

    fputs("runtime ticket-zero allocator ok\n", stdout);
    return 0;
}
