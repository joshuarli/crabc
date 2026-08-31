/* Static crabc-libc x86-64 GNU CPU-count helper fixture.
 *
 * The same project-header C body executes first through pinned musl 1.2.6
 * and then through a freestanding candidate linked solely with the selected
 * crabc archive. It admits only bytewise counts over valid caller-owned
 * cpu_set_t storage and the two musl count macros. It is not affinity,
 * scheduler-policy, CPU-topology, timer/clock, timezone/calendar, CRT,
 * loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

#ifndef CPU_COUNT_S
#error "CPU_COUNT_S must be visible under _GNU_SOURCE"
#endif
#ifndef CPU_COUNT
#error "CPU_COUNT must be visible under _GNU_SOURCE"
#endif

_Static_assert(sizeof(cpu_set_t) == 128, "x86 cpu_set_t width");
_Static_assert(_Alignof(cpu_set_t) == _Alignof(unsigned long),
    "x86 cpu_set_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__sched_cpucount),
    int (*)(size_t, const cpu_set_t *)), "__sched_cpucount declaration");

typedef int (*sched_cpucount_function)(size_t, const cpu_set_t *);

static sched_cpucount_function volatile direct_sched_cpucount =
    __sched_cpucount;
static cpu_set_t sample_set;

static void clear_sample(void)
{
    unsigned char *bytes = (unsigned char *)(void *)&sample_set;
    size_t index;

    for (index = 0; index < sizeof(sample_set); index++)
        bytes[index] = 0;
}

static int check_partial_sizes(void)
{
    unsigned char *bytes = (unsigned char *)(void *)&sample_set;

    clear_sample();
    bytes[0] = 0x81;
    bytes[1] = 0x12;
    bytes[6] = 0x80;
    bytes[7] = 0x7f;
    bytes[126] = 0xff;
    bytes[127] = 0x01;

    if (direct_sched_cpucount(0, &sample_set) != 0)
        return 1;
    if (direct_sched_cpucount(1, &sample_set) != 2)
        return 2;
    if (CPU_COUNT_S(2, &sample_set) != 4)
        return 3;
    if (direct_sched_cpucount(7, &sample_set) != 5)
        return 4;
    if (CPU_COUNT_S(8, &sample_set) != 12)
        return 5;
    if (direct_sched_cpucount(127, &sample_set) != 20)
        return 6;
    if (CPU_COUNT(&sample_set) != 21)
        return 7;
    return 0;
}

static int check_full_mask(void)
{
    unsigned char *bytes = (unsigned char *)(void *)&sample_set;
    size_t index;

    for (index = 0; index < sizeof(sample_set); index++)
        bytes[index] = 0xff;
    if (direct_sched_cpucount(sizeof(sample_set), &sample_set) !=
        (int)(sizeof(sample_set) * 8))
        return 1;
    if (CPU_COUNT_S(sizeof(sample_set), &sample_set) !=
        (int)(sizeof(sample_set) * 8))
        return 2;
    if (CPU_COUNT(&sample_set) != (int)(sizeof(sample_set) * 8))
        return 3;
    return 0;
}

int crabc_x86_64_sched_cpucount_probe(void)
{
    int status = check_partial_sizes();

    if (status != 0)
        return 10 + status;
    status = check_full_mask();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_SCHED_CPUCOUNT_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_cpucount_probe();
}
#endif
