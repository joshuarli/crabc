/*
 * Installed-product differential for the eighteen residual spellings in the
 * frozen system.kernel-admin roster.  Every selector succeeds against musl;
 * the runner invokes selectors independently so a source-loop failure cannot
 * conceal a later raw-error or namespace boundary.
 */
#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/membarrier.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <ulimit.h>
#include <unistd.h>

/* The installed project headers intentionally do not project Linux's seccomp
 * UAPI. This fixture copies only the exact Linux 5.10 classic-BPF records and
 * constants passed through the existing variadic `prctl` ABI; it neither
 * installs nor expands a public header. `seccomp_data.nr` begins at byte 0. */
struct sock_filter {
    unsigned short code;
    unsigned char jump_true;
    unsigned char jump_false;
    unsigned int constant;
};

struct sock_fprog {
    unsigned short length;
    struct sock_filter *filter;
};

#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JMP 0x05
#define BPF_JEQ 0x10
#define BPF_K 0x00
#define BPF_RET 0x06
#define BPF_STMT(code, constant) { (unsigned short)(code), 0, 0, (constant) }
#define BPF_JUMP(code, constant, true_offset, false_offset) \
    { (unsigned short)(code), (true_offset), (false_offset), (constant) }
#define SECCOMP_MODE_STRICT 1U
#define SECCOMP_MODE_FILTER 2U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

_Static_assert(PR_SET_SECCOMP == 22, "Linux 5.10 PR_SET_SECCOMP");
_Static_assert(PR_SET_NO_NEW_PRIVS == 38, "Linux 5.10 PR_SET_NO_NEW_PRIVS");
_Static_assert(SECCOMP_MODE_STRICT == 1U, "Linux 5.10 seccomp strict mode");
_Static_assert(SECCOMP_MODE_FILTER == 2U, "Linux 5.10 seccomp filter mode");
_Static_assert(sizeof(struct sock_filter) == 8, "Linux 5.10 sock_filter");
_Static_assert(sizeof(struct sock_fprog) == 16, "Linux 5.10 x86-64 sock_fprog");
_Static_assert(offsetof(struct sock_fprog, filter) == 8, "Linux 5.10 x86-64 sock_fprog filter");

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "owned-kernel-residual:%s:%d errno=%d\n", \
                __func__, __LINE__, errno); \
            return 1; \
        } \
    } while (0)

static long raw6(long number, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return result;
}

static void transcript_raw_negative(
    const char *operation, long raw_result, long c_result, int c_error)
{
    int saved_errno = errno;

    printf("owned-kernel-residual-raw-negative operation=%s raw_result=%ld raw_errno=%ld c_result=%ld c_errno=%d\n",
        operation, raw_result, -raw_result, c_result, c_error);
    errno = saved_errno;
}

#define ERROR_MATCH(operation, call, number, a, b, c, d, e, f) \
    do { \
        long raw_result; \
        long c_result; \
        int c_error; \
        errno = E2BIG; \
        raw_result = raw6((number), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f)); \
        CHECK(raw_result < 0 && raw_result >= -4095 && errno == E2BIG); \
        errno = ERANGE; \
        c_result = (long)(call); \
        c_error = errno; \
        CHECK(c_result == -1 && c_error == -raw_result); \
        transcript_raw_negative((operation), raw_result, c_result, c_error); \
    } while (0)

static int cpucount_case(void)
{
    cpu_set_t set;
    unsigned char *bytes = (unsigned char *)&set;

    memset(&set, 0, sizeof set);
    bytes[0] = 0x91;
    bytes[17] = 0x80;
    bytes[sizeof set - 1] = 0x03;
    errno = E2BIG;
    CHECK(__sched_cpucount(sizeof set, &set) == 6 && errno == E2BIG);
    CHECK(__sched_cpucount(18, &set) == 4 && errno == E2BIG);
    return 0;
}

static int configuration_case(void)
{
    static const char path[] = "/bin:/usr/bin";
    char buffer[sizeof path];
    struct rlimit limit;
    long expected_descriptors;

    memset(buffer, 0xa5, sizeof buffer);
    errno = E2BIG;
    CHECK(confstr(_CS_PATH, NULL, 0) == sizeof path && errno == E2BIG);
    CHECK(confstr(_CS_PATH, buffer, 5) == sizeof path && errno == E2BIG);
    CHECK(!memcmp(buffer, "/bin\0", 5));
    memset(buffer, 0xa5, sizeof buffer);
    CHECK(confstr(_CS_PATH, buffer, sizeof buffer) == sizeof path);
    CHECK(!memcmp(buffer, path, sizeof path));
    errno = E2BIG;
    CHECK(confstr(_CS_POSIX_V7_THREADS_LDFLAGS, buffer, sizeof buffer) == 1
        && buffer[0] == 0 && errno == E2BIG);
    errno = E2BIG;
    CHECK(confstr(INT_MAX, buffer, sizeof buffer) == 0 && errno == EINVAL);

    errno = E2BIG;
    CHECK(fpathconf(-1, _PC_ASYNC_IO) == -1 && errno == E2BIG);
    CHECK(pathconf(NULL, _PC_LINK_MAX) == _POSIX_LINK_MAX && errno == E2BIG);
    errno = E2BIG;
    CHECK(fpathconf(-1, INT_MAX) == -1 && errno == EINVAL);
    errno = E2BIG;
    CHECK(pathconf(NULL, INT_MAX) == -1 && errno == EINVAL);

    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    expected_descriptors = limit.rlim_cur < (rlim_t)INT_MAX ? (long)limit.rlim_cur : INT_MAX;
    errno = E2BIG;
    CHECK(getdtablesize() == expected_descriptors && errno == E2BIG);
    return 0;
}

static int sysconf_signal_stack_case(void)
{
    unsigned long frame_size;
    unsigned long expected_minimum;

    frame_size = getauxval(AT_MINSIGSTKSZ);
    expected_minimum = MINSIGSTKSZ - 1024;
    if (frame_size < expected_minimum) frame_size = expected_minimum;
    expected_minimum = frame_size + 1024;

    errno = E2BIG;
    CHECK(sysconf(_SC_CLK_TCK) == 100 && errno == E2BIG);
    CHECK(sysconf(_SC_PAGE_SIZE) == 4096 && errno == E2BIG);
    CHECK(sysconf(_SC_MINSIGSTKSZ) == (long)expected_minimum && errno == E2BIG);
    CHECK(sysconf(_SC_SIGSTKSZ) == (long)(expected_minimum + SIGSTKSZ - MINSIGSTKSZ)
        && errno == E2BIG);
    errno = E2BIG;
    CHECK(sysconf(INT_MAX) == -1 && errno == EINVAL);
    return 0;
}

static int child_result(int (*body)(void));

/* musl's page arithmetic over one sysinfo sample. */
static unsigned long long sysinfo_pages(int available)
{
    struct sysinfo info;
    unsigned long long memory;

    if (sysinfo(&info)) return 0;
    if (!info.mem_unit) info.mem_unit = 1;
    memory = available ? info.freeram + info.bufferram : info.totalram;
    return memory * info.mem_unit / 4096;
}

/* Rlimit-derived selectors, in a child so lowered limits cannot reach later
 * selectors: a finite soft limit is returned as is, and RLIM_INFINITY is -1
 * without touching errno. */
static int sysconf_rlimit_child(void)
{
    struct rlimit limit;

    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    limit.rlim_cur = 77;
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    errno = E2BIG;
    CHECK(sysconf(_SC_OPEN_MAX) == 77 && errno == E2BIG);
    CHECK(getrlimit(RLIMIT_NPROC, &limit) == 0);
    if (limit.rlim_max == RLIM_INFINITY) {
        limit.rlim_cur = RLIM_INFINITY;
        CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
        errno = E2BIG;
        CHECK(sysconf(_SC_CHILD_MAX) == -1 && errno == E2BIG);
        printf("sysconf child-max infinite\n");
    } else {
        printf("sysconf child-max bounded %lld\n", (long long)limit.rlim_max);
    }
    return 0;
}

/* Print every sysconf selector's raw result and errno so each product's
 * complete musl table is compared with pinned musl in the same container.
 * Free memory moves between processes, so _SC_AVPHYS_PAGES is instead
 * bracketed by samples taken in this process. */
static int sysconf_table_case(void)
{
    unsigned long long before;
    unsigned long long after;
    long value;
    int name;

    for (name = -3; name <= 260; name++) {
        if (name == _SC_AVPHYS_PAGES) continue;
        errno = E2BIG;
        value = sysconf(name);
        printf("sysconf %d %ld %d\n", name, value, errno);
    }
    errno = E2BIG;
    CHECK(sysconf(INT_MIN) == -1 && errno == EINVAL);
    errno = E2BIG;
    CHECK(sysconf(INT_MAX) == -1 && errno == EINVAL);

    before = sysinfo_pages(1);
    errno = E2BIG;
    value = sysconf(_SC_AVPHYS_PAGES);
    CHECK(errno == E2BIG);
    after = sysinfo_pages(1);
    if (after < before) {
        unsigned long long swap = before;
        before = after;
        after = swap;
    }
    /* Allow 1/64 of physical memory of churn around the two samples. */
    CHECK(value > 0 && (unsigned long long)value <= sysinfo_pages(0)
        && (unsigned long long)value + sysinfo_pages(0) / 64 >= before
        && (unsigned long long)value <= after + sysinfo_pages(0) / 64);
    printf("sysconf avphys bracketed\n");

    return child_result(sysconf_rlimit_child);
}

static int hostid_and_membarrier_case(void)
{
    int query;

    errno = E2BIG;
    CHECK(gethostid() == 0 && errno == E2BIG);
    errno = E2BIG;
    query = membarrier(MEMBARRIER_CMD_QUERY, 0);
    CHECK(query >= 0 && errno == E2BIG);
    ERROR_MATCH("membarrier-invalid", membarrier(-1, 0), SYS_membarrier,
        -1, 0, 0, 0, 0, 0);
    return 0;
}

static int personality_case(void)
{
    long raw_result;
    long c_result;
    int c_error;

    errno = E2BIG;
    raw_result = raw6(SYS_personality, -1L, 0, 0, 0, 0, 0);
    CHECK(errno == E2BIG);
    errno = ERANGE;
    c_result = personality(~0UL);
    c_error = errno;
    if (raw_result < 0) {
        CHECK(raw_result >= -4095);
        CHECK(c_result == -1 && c_error == -raw_result);
        transcript_raw_negative("personality-query", raw_result, c_result, c_error);
    } else {
        CHECK(c_result == raw_result && c_error == ERANGE);
    }
    return 0;
}

static int prctl_case(void)
{
    long raw_result;

    errno = E2BIG;
    raw_result = raw6(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0, 0);
    CHECK(raw_result >= 0 && errno == E2BIG);
    errno = ERANGE;
    CHECK(prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == raw_result && errno == ERANGE);
    ERROR_MATCH("prctl-invalid", prctl(-1, 0UL, 0UL, 0UL, 0UL),
        SYS_prctl, -1, 0, 0, 0, 0, 0);
    return 0;
}

static int scheduler_case(void)
{
    const int pids[] = { 0, -1, INT_MAX };
    struct sched_param parameter;
    unsigned char untouched[sizeof parameter];
    size_t index;

    memset(&parameter, 0xa5, sizeof parameter);
    memcpy(untouched, &parameter, sizeof untouched);
    for (index = 0; index < sizeof pids / sizeof pids[0]; ++index) {
        errno = E2BIG;
        CHECK(sched_getparam(pids[index], &parameter) == -1 && errno == ENOSYS);
        CHECK(!memcmp(&parameter, untouched, sizeof parameter));
        errno = E2BIG;
        CHECK(sched_getscheduler(pids[index]) == -1 && errno == ENOSYS);
        errno = E2BIG;
        CHECK(sched_setparam(pids[index], &parameter) == -1 && errno == ENOSYS);
        CHECK(!memcmp(&parameter, untouched, sizeof parameter));
        errno = E2BIG;
        CHECK(sched_setscheduler(pids[index], SCHED_OTHER, &parameter) == -1 && errno == ENOSYS);
        CHECK(!memcmp(&parameter, untouched, sizeof parameter));
    }
    errno = E2BIG;
    CHECK(sched_getparam(0, NULL) == -1 && errno == ENOSYS);
    CHECK(sched_setparam(0, NULL) == -1 && errno == ENOSYS);
    CHECK(sched_setscheduler(0, INT_MAX, NULL) == -1 && errno == ENOSYS);
    return 0;
}

static int syscall_case(void)
{
    errno = E2BIG;
    CHECK(syscall(SYS_getpid, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL) == getpid()
        && errno == E2BIG);
    ERROR_MATCH("syscall-invalid", syscall(-1L, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL),
        -1L, 0, 0, 0, 0, 0, 0);
    return 0;
}

static int ulimit_child_case(void)
{
    struct rlimit limit;
    long expected;

    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0);
    expected = (long)(limit.rlim_cur / 512);
    errno = E2BIG;
    CHECK(ulimit(UL_GETFSIZE) == expected && errno == E2BIG);
    CHECK(ulimit(INT_MAX) == expected && errno == E2BIG);
    errno = E2BIG;
    CHECK(ulimit(UL_SETFSIZE, 1L) == 1 && errno == E2BIG);
    CHECK(ulimit(UL_GETFSIZE) == 1 && errno == E2BIG);
    return 0;
}

static int child_result(int (*body)(void))
{
    pid_t child;
    int status;

    /* Do not let a child flush an inherited transcript when its contained
     * body publishes its own raw kernel observation before `_exit`. */
    CHECK(fflush(stdout) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int result = body();

        if (fflush(stdout)) _exit(2);
        _exit(result ? 1 : 0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int ulimit_case(void)
{
    return child_result(ulimit_child_case);
}

static int uts_namespace_child(void)
{
    char hostname[] = "crabc-kernel-residual";
    char domainname[] = "crabc-residual";
    char observed_hostname[256];
    char observed_domainname[256];
    long raw_result;
    int result;
    int c_error;

    errno = E2BIG;
    result = unshare(CLONE_NEWUTS);
    c_error = errno;
    if (result) {
        CHECK(c_error == EPERM || c_error == EINVAL);
        errno = ERANGE;
        raw_result = raw6(SYS_unshare, CLONE_NEWUTS, 0, 0, 0, 0, 0);
        CHECK(raw_result == -c_error && errno == ERANGE);
        transcript_raw_negative("unshare-new-uts", raw_result, result, c_error);
        return 0;
    }
    errno = E2BIG;
    result = sethostname(hostname, sizeof hostname - 1);
    c_error = errno;
    if (result) {
        CHECK(c_error == EPERM || c_error == EACCES);
        errno = ERANGE;
        raw_result = raw6(SYS_sethostname, (long)hostname, sizeof hostname - 1,
            0, 0, 0, 0);
        CHECK(raw_result == -c_error && errno == ERANGE);
        transcript_raw_negative("sethostname-private-uts", raw_result, result, c_error);
        return 0;
    }
    CHECK(c_error == E2BIG);
    errno = E2BIG;
    result = setdomainname(domainname, sizeof domainname - 1);
    c_error = errno;
    if (result) {
        CHECK(c_error == EPERM || c_error == EACCES);
        errno = ERANGE;
        raw_result = raw6(SYS_setdomainname, (long)domainname, sizeof domainname - 1,
            0, 0, 0, 0);
        CHECK(raw_result == -c_error && errno == ERANGE);
        transcript_raw_negative("setdomainname-private-uts", raw_result, result, c_error);
        return 0;
    }
    CHECK(c_error == E2BIG);
    CHECK(gethostname(observed_hostname, sizeof observed_hostname) == 0);
    CHECK(getdomainname(observed_domainname, sizeof observed_domainname) == 0);
    CHECK(!strcmp(observed_hostname, hostname));
    CHECK(!strcmp(observed_domainname, domainname));
    puts("owned-kernel-residual-private-uts-ok");
    return 0;
}

static int uts_namespace_case(void)
{
    return child_result(uts_namespace_child);
}

static int uts_seccomp_child(void)
{
    char hostname[] = "crabc-kernel-residual";
    char domainname[] = "crabc-residual";
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sethostname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setdomainname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .length = sizeof instructions / sizeof instructions[0],
        .filter = instructions,
    };
    long raw_result;
    long c_result;
    int c_error;

    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == 0);
    /* If this fails, stop before either setter. The valid-pointer negative
     * checks below are contained only by this installed classic-BPF filter. */
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&program, 0UL, 0UL) == 0);
    puts("owned-kernel-residual-seccomp-filter-installed");

    errno = E2BIG;
    raw_result = raw6(SYS_sethostname, (long)hostname, sizeof hostname - 1, 0, 0, 0, 0);
    CHECK(raw_result == -EPERM && errno == E2BIG);
    errno = ERANGE;
    c_result = sethostname(hostname, sizeof hostname - 1);
    c_error = errno;
    CHECK(c_result == -1 && c_error == EPERM);
    transcript_raw_negative("sethostname-seccomp", raw_result, c_result, c_error);
    errno = E2BIG;
    raw_result = raw6(SYS_setdomainname, (long)domainname, sizeof domainname - 1, 0, 0, 0, 0);
    CHECK(raw_result == -EPERM && errno == E2BIG);
    errno = ERANGE;
    c_result = setdomainname(domainname, sizeof domainname - 1);
    c_error = errno;
    CHECK(c_result == -1 && c_error == EPERM);
    transcript_raw_negative("setdomainname-seccomp", raw_result, c_result, c_error);
    return 0;
}

static int uts_seccomp_case(void)
{
    return child_result(uts_seccomp_child);
}

/* Musl 1.2.6 `__membarrier` emulates MEMBARRIER_CMD_PRIVATE_EXPEDITED when
 * the kernel refuses it, which Linux 5.10 does for any process that has not
 * registered: it catches every other thread with SIGSYNCCALL and succeeds.
 * `__pthread_create` registers the process before its first thread. The raw
 * SIGSYNCCALL (34) disposition exposes the emulation's final SIG_IGN reset. */
#define SIGSYNCCALL_NUMBER 34

static long synccall_disposition(void)
{
    unsigned long action[4] = { 0 };
    long result = raw6(SYS_rt_sigaction, SIGSYNCCALL_NUMBER, 0, (long)action, 8, 0, 0);

    return result ? result : (long)action[0];
}

/* An exec preserves an inherited SIG_IGN, so start from the default. */
static long reset_synccall_disposition(void)
{
    unsigned long action[4] = { (unsigned long)SIG_DFL, 0, 0, 0 };

    return raw6(SYS_rt_sigaction, SIGSYNCCALL_NUMBER, (long)action, 0, 8, 0, 0);
}

static long raw_private_expedited(void)
{
    return raw6(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0, 0, 0, 0);
}

static void *membarrier_idle_thread(void *argument)
{
    (void)argument;
    return 0;
}

static int membarrier_unregistered_child(void)
{
    pthread_t thread;

    CHECK(reset_synccall_disposition() == 0);
    CHECK(synccall_disposition() == (long)SIG_DFL);
    CHECK(raw_private_expedited() == -EPERM);
    errno = E2BIG;
    CHECK(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0) == 0 && errno == E2BIG);
    CHECK(synccall_disposition() == (long)SIG_IGN);
    /* The emulation neither registers nor covers flagged requests. */
    CHECK(raw_private_expedited() == -EPERM);
    ERROR_MATCH("membarrier-expedited-flagged",
        membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 1), SYS_membarrier,
        MEMBARRIER_CMD_PRIVATE_EXPEDITED, 1, 0, 0, 0, 0);
    CHECK(pthread_create(&thread, 0, membarrier_idle_thread, 0) == 0);
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(raw_private_expedited() == 0);
    errno = E2BIG;
    CHECK(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0) == 0 && errno == E2BIG);
    puts("membarrier first-thread registration");
    return 0;
}

#define MEMBARRIER_EMULATED_THREADS 4

static volatile int membarrier_interrupted[MEMBARRIER_EMULATED_THREADS];

/* ppoll is never restarted after a handler, so only the emulation's
 * SIGSYNCCALL can end this wait early. */
static void *membarrier_waiting_thread(void *argument)
{
    volatile int *interrupted = argument;
    struct timespec second = { 1, 0 };
    int round;

    for (round = 0; round < 20; round++) {
        if (ppoll(0, 0, &second, 0) == -1 && errno == EINTR) {
            *interrupted = 1;
            return 0;
        }
    }
    return argument;
}

static int membarrier_emulated_child(void)
{
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_membarrier, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .length = sizeof instructions / sizeof instructions[0],
        .filter = instructions,
    };
    pthread_t threads[MEMBARRIER_EMULATED_THREADS];
    int index;
    int attempt;
    int caught;

    CHECK(reset_synccall_disposition() == 0);
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == 0);
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&program, 0UL, 0UL) == 0);
    for (index = 0; index < MEMBARRIER_EMULATED_THREADS; index++) {
        CHECK(pthread_create(&threads[index], 0, membarrier_waiting_thread,
            (void *)&membarrier_interrupted[index]) == 0);
    }
    /* Registration was refused, so the multi-threaded call is emulated. */
    CHECK(raw_private_expedited() == -EPERM);
    for (attempt = 0, caught = 0; attempt < 2000 && caught < MEMBARRIER_EMULATED_THREADS; attempt++) {
        struct timespec delay = { 0, 1000000 };

        /* Musl's semaphore wait may leave EAGAIN from its sem_trywait fast
         * path, depending on timing; success leaves errno unspecified. */
        CHECK(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0) == 0);
        for (index = 0, caught = 0; index < MEMBARRIER_EMULATED_THREADS; index++) {
            caught += membarrier_interrupted[index];
        }
        nanosleep(&delay, 0);
    }
    for (index = 0; index < MEMBARRIER_EMULATED_THREADS; index++) {
        void *result;

        CHECK(pthread_join(threads[index], &result) == 0 && result == 0);
    }
    CHECK(synccall_disposition() == (long)SIG_IGN);
    puts("membarrier emulated all-thread barrier");
    return 0;
}

static int membarrier_expedited_case(void)
{
    return child_result(membarrier_unregistered_child)
        || child_result(membarrier_emulated_child);
}

static int run_selected(const char *selector)
{
    if (!strcmp(selector, "cpucount")) return cpucount_case();
    if (!strcmp(selector, "configuration")) return configuration_case();
    if (!strcmp(selector, "sysconf-signal-stack")) return sysconf_signal_stack_case();
    if (!strcmp(selector, "sysconf-table")) return sysconf_table_case();
    if (!strcmp(selector, "hostid-membarrier")) return hostid_and_membarrier_case();
    if (!strcmp(selector, "membarrier-expedited")) return membarrier_expedited_case();
    if (!strcmp(selector, "personality")) return personality_case();
    if (!strcmp(selector, "prctl")) return prctl_case();
    if (!strcmp(selector, "scheduler")) return scheduler_case();
    if (!strcmp(selector, "syscall")) return syscall_case();
    if (!strcmp(selector, "ulimit")) return ulimit_case();
    if (!strcmp(selector, "uts-namespace")) return uts_namespace_case();
    if (!strcmp(selector, "uts-seccomp")) return uts_seccomp_case();
    if (strcmp(selector, "all")) {
        errno = EINVAL;
        return 1;
    }
    return cpucount_case()
        || configuration_case()
        || sysconf_signal_stack_case()
        || sysconf_table_case()
        || hostid_and_membarrier_case()
        || membarrier_expedited_case()
        || personality_case()
        || prctl_case()
        || scheduler_case()
        || syscall_case()
        || ulimit_case()
        || uts_namespace_case()
        || uts_seccomp_case();
}

int main(int argc, char **argv)
{
    const char *selector;

    if (argc == 1) selector = "all";
    else if (argc == 2) selector = argv[1];
    else selector = "invalid";
    if (run_selected(selector)) {
        fprintf(stderr, "owned-kernel-residual %s failure errno=%d\n", selector, errno);
        return 1;
    }
    printf("owned-kernel-residual-%s-ok\n", selector);
    return 0;
}
