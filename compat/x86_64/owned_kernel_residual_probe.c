/*
 * Installed-product differential for the eighteen residual spellings in the
 * frozen system.kernel-admin roster.  Every selector succeeds against musl;
 * the runner invokes selectors independently so a source-loop failure cannot
 * conceal a later raw-error or namespace boundary.
 */
#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
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
#include <sys/wait.h>
#include <ulimit.h>
#include <unistd.h>

/* The installed project headers intentionally do not project Linux's seccomp
 * UAPI. This fixture uses only the exact Linux 5.10 classic-BPF record and
 * constants it passes through the existing variadic `prctl` ABI; it neither
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
#define SECCOMP_MODE_FILTER 1U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

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

#define ERROR_MATCH(call, number, a, b, c, d, e, f) \
    do { \
        long raw_result; \
        errno = E2BIG; \
        raw_result = raw6((number), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f)); \
        CHECK(raw_result < 0 && raw_result >= -4095 && errno == E2BIG); \
        errno = ERANGE; \
        CHECK((call) == -1 && errno == -raw_result); \
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

static int hostid_and_membarrier_case(void)
{
    int query;

    errno = E2BIG;
    CHECK(gethostid() == 0 && errno == E2BIG);
    errno = E2BIG;
    query = membarrier(MEMBARRIER_CMD_QUERY, 0);
    CHECK(query >= 0 && errno == E2BIG);
    ERROR_MATCH(membarrier(-1, 0), SYS_membarrier, -1, 0, 0, 0, 0, 0);
    return 0;
}

static int personality_case(void)
{
    long raw_result;

    errno = E2BIG;
    raw_result = raw6(SYS_personality, -1L, 0, 0, 0, 0, 0);
    CHECK(errno == E2BIG);
    errno = ERANGE;
    if (raw_result < 0) {
        CHECK(raw_result >= -4095);
        CHECK(personality(~0UL) == -1 && errno == -raw_result);
    } else {
        CHECK(personality(~0UL) == raw_result && errno == ERANGE);
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
    ERROR_MATCH(
        prctl(-1, 0UL, 0UL, 0UL, 0UL), SYS_prctl, -1, 0, 0, 0, 0, 0
    );
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
    ERROR_MATCH(
        syscall(-1L, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL), -1L, 0, 0, 0, 0, 0, 0
    );
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

    child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(body() ? 1 : 0);
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

    if (unshare(CLONE_NEWUTS)) {
        CHECK(errno == EPERM || errno == EINVAL);
        puts("owned-kernel-residual-private-uts-unavailable");
        return 0;
    }
    errno = E2BIG;
    if (sethostname(hostname, sizeof hostname - 1)
        || setdomainname(domainname, sizeof domainname - 1)) {
        CHECK(errno == EPERM || errno == EACCES);
        puts("owned-kernel-residual-private-uts-unavailable");
        return 0;
    }
    CHECK(errno == E2BIG);
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
    int filter_installed = 0;

    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == 0);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&program, 0UL, 0UL)) {
        /* The pinned container may disable filter installation. The valid
         * pointer calls below still prove the contained capability-negative
         * wrapper/raw-error boundary without claiming seccomp availability. */
        CHECK(errno == EINVAL || errno == EPERM);
        puts("owned-kernel-residual-seccomp-unavailable");
    } else {
        filter_installed = 1;
    }

    errno = E2BIG;
    raw_result = raw6(SYS_sethostname, (long)hostname, sizeof hostname - 1, 0, 0, 0, 0);
    CHECK(raw_result < 0 && raw_result >= -4095 && errno == E2BIG);
    if (filter_installed) CHECK(raw_result == -EPERM);
    errno = ERANGE;
    CHECK(sethostname(hostname, sizeof hostname - 1) == -1 && errno == -raw_result);
    errno = E2BIG;
    raw_result = raw6(SYS_setdomainname, (long)domainname, sizeof domainname - 1, 0, 0, 0, 0);
    CHECK(raw_result < 0 && raw_result >= -4095 && errno == E2BIG);
    if (filter_installed) CHECK(raw_result == -EPERM);
    errno = ERANGE;
    CHECK(setdomainname(domainname, sizeof domainname - 1) == -1 && errno == -raw_result);
    return 0;
}

static int uts_seccomp_case(void)
{
    return child_result(uts_seccomp_child);
}

static int run_selected(const char *selector)
{
    if (!strcmp(selector, "cpucount")) return cpucount_case();
    if (!strcmp(selector, "configuration")) return configuration_case();
    if (!strcmp(selector, "sysconf-signal-stack")) return sysconf_signal_stack_case();
    if (!strcmp(selector, "hostid-membarrier")) return hostid_and_membarrier_case();
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
        || hostid_and_membarrier_case()
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
