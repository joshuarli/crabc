/* Static Linux/x86-64 membarrier C ABI and pinned-musl behavior fixture.
 *
 * The one shared body calls only the read-only QUERY operation and direct
 * invalid-command/invalid-flag error paths. It compares each wrapper result
 * with an adjacent raw syscall so the selected evidence never registers a
 * command, enters an expedited/global barrier, changes RSEQ state, or claims
 * a process-wide memory-ordering policy. Pinned musl's separate old-kernel
 * PRIVATE_EXPEDITED fallback and __membarrier_init registration hook are
 * deliberately outside this Linux 5.10 direct-branch fixture.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/membarrier.h>
#include <sys/syscall.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_membarrier == 324, "x86 membarrier syscall number");
_Static_assert(MEMBARRIER_CMD_QUERY == 0 && MEMBARRIER_CMD_GLOBAL == 1,
    "selected membarrier command words");
_Static_assert(MEMBARRIER_CMD_FLAG_CPU == 1, "selected membarrier flag word");

typedef int (*membarrier_signature)(int, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&membarrier),
    membarrier_signature), "membarrier declaration");

static long raw_syscall2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static int check_query_direct_and_indirect(void)
{
    const membarrier_signature indirect = membarrier;
    long raw_before;
    long raw_after;
    int direct;
    int through_pointer;

    raw_before = raw_syscall2(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0);
    if (raw_before < 0)
        return 1;
    errno = E2BIG;
    direct = membarrier(MEMBARRIER_CMD_QUERY, 0);
    if (direct != raw_before)
        return 2;
    if (errno != E2BIG)
        return 3;
    raw_after = raw_syscall2(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0);
    if (raw_after < 0)
        return 4;
    errno = ERANGE;
    through_pointer = indirect(MEMBARRIER_CMD_QUERY, 0);
    if (through_pointer != raw_after)
        return 5;
    if (errno != ERANGE)
        return 6;
    return 0;
}

static int check_invalid_command(void)
{
    long raw = raw_syscall2(SYS_membarrier, -1, 0);

    if (raw != -EINVAL)
        return 1;
    errno = E2BIG;
    if (membarrier(-1, 0) != -1)
        return 2;
    if (errno != EINVAL)
        return 3;
    return 0;
}

static int check_invalid_query_flag(void)
{
    long raw = raw_syscall2(SYS_membarrier, MEMBARRIER_CMD_QUERY,
        MEMBARRIER_CMD_FLAG_CPU);

    if (raw != -EINVAL)
        return 1;
    errno = ERANGE;
    if (membarrier(MEMBARRIER_CMD_QUERY, MEMBARRIER_CMD_FLAG_CPU) != -1)
        return 2;
    if (errno != EINVAL)
        return 3;
    return 0;
}

int crabc_x86_64_membarrier_probe(void)
{
    int result = check_query_direct_and_indirect();

    if (result != 0)
        return result;
    result = check_invalid_command();
    if (result != 0)
        return 10 + result;
    result = check_invalid_query_flag();
    return result == 0 ? 0 : 20 + result;
}

#ifndef CRABC_MEMBARRIER_FREESTANDING
int main(void)
{
    return crabc_x86_64_membarrier_probe();
}
#endif
