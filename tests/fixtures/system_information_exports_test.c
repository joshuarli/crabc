#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <sys/timeb.h>
#include <time.h>
#include <unistd.h>

extern int getloadavg(double *, int);

int main(void)
{
    struct sysinfo info;
    struct timeb stamp;
    struct timespec before;
    struct timespec after;
    struct timespec cpu;
    double loads[3];
    clockid_t cpu_clock;
    int n;
    int i;
    long physical;
    long available;

    if (sysinfo(&info) != 0 || info.mem_unit == 0 || info.totalram == 0 ||
        info.procs == 0)
        return 1;
    errno = 0;
    if (sysinfo(NULL) != -1 || errno != EFAULT)
        return 2;

    if (getloadavg(loads, 4) != 3)
        return 3;
    for (i = 0; i < 3; i++) {
        if (loads[i] < 0.0 || loads[i] > 1000000000.0)
            return 4;
    }
    if (getloadavg(loads, 0) != 0 || getloadavg(loads, -1) != -1)
        return 5;

    n = get_nprocs();
    if (n <= 0 || get_nprocs_conf() < n)
        return 6;
    physical = get_phys_pages();
    available = get_avphys_pages();
    if (physical <= 0 || available < 0 || available > physical)
        return 7;

    if (clock_gettime(CLOCK_REALTIME, &before) != 0)
        return 8;
    if (ftime(&stamp) != 0)
        return 9;
    if (clock_gettime(CLOCK_REALTIME, &after) != 0 ||
        stamp.millitm >= 1000 || stamp.time < before.tv_sec - 1 ||
        stamp.time > after.tv_sec + 1 || stamp.timezone != 0 ||
        stamp.dstflag != 0)
        return 10;

    if (clock_getcpuclockid(getpid(), &cpu_clock) != 0 ||
        clock_gettime(cpu_clock, &cpu) != 0 || cpu.tv_sec < 0 ||
        cpu.tv_nsec < 0 || cpu.tv_nsec >= 1000000000L)
        return 11;
    if (clock_getcpuclockid(INT_MAX - 1, &cpu_clock) != ESRCH)
        return 12;

    puts("c-abi system information exports ok");
    return 0;
}
