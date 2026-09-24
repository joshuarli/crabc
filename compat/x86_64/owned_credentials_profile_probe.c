/* Installed x86-64 credential-setter differential.
 *
 * The nine setters follow musl: each Linux credential syscall runs on every
 * thread of the process through the `__synccall` rendezvous. The
 * single-threaded subcases perform each call in a fresh child of the
 * disposable user-namespace process.
 *
 * The direct subcase exercises successful explicit current-ID calls for every
 * uid/gid setter, plus Linux's all-ones no-change words for setresuid and
 * setresgid and unmapped-ID rejection for setuid/setgid. The mapped user
 * namespace deliberately denies setgroups; that call supplies a valid live
 * one-element gid_t slice and expects EPERM before any ID transition. Every
 * child records its raw status and errno with real/effective/saved IDs before
 * and after the call. The historical aliases (setreuid, seteuid, setregid,
 * setegid) use unchanged IDs too and must succeed.
 *
 * The `transitions` subcase runs as the container's real root, outside a user
 * namespace, and performs actual ID changes in disposable single-threaded
 * children: supplementary-group replacement and clearing, distinct
 * real/effective/saved uid and gid words, unprivileged saved-ID exchanges and
 * EPERM rejection, and root `setuid`/`setgid` collapsing all three IDs. Every
 * step records the raw status and errno plus the raw kernel IDs afterward.
 *
 * The `threads` subcase, also as real root, proves the all-thread contract.
 * In disposable children with live workers parked in a condition wait, a
 * spin loop, and a restartable pipe read, it changes groups and every ID
 * word through each of the nine setters, from the initial thread and from a
 * worker, and after the initial thread has called pthread_exit; every
 * thread then reports its own raw kernel IDs, and the interrupted read must
 * complete with its data. An unprivileged EPERM on the first caught thread
 * is reported without changing any thread. A churn case repeats effective-ID
 * toggles while other threads are continuously created, joined, detached,
 * forked (a `_Fork` child changes its own IDs), and targeted by pthread_kill
 * and pthread_getschedparam, so the rendezvous meets threads entering and
 * leaving the process and threads inside a thread-list lookup.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "credentials profile requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t width");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "x86 uid_t width");
_Static_assert(sizeof(gid_t) == sizeof(uint32_t), "x86 gid_t width");
_Static_assert(_Alignof(uid_t) == _Alignof(uint32_t), "x86 uid_t alignment");
_Static_assert(_Alignof(gid_t) == _Alignof(uint32_t), "x86 gid_t alignment");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
_Static_assert(SYS_getresuid == 118, "x86 getresuid syscall number");
_Static_assert(SYS_getresgid == 120, "x86 getresgid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setgroups),
    int (*)(size_t, const gid_t *)), "setgroups declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setuid), int (*)(uid_t)),
    "setuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setgid), int (*)(gid_t)),
    "setgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setresuid),
    int (*)(uid_t, uid_t, uid_t)), "setresuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setresgid),
    int (*)(gid_t, gid_t, gid_t)), "setresgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&seteuid), int (*)(uid_t)),
    "seteuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setegid), int (*)(gid_t)),
    "setegid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setreuid),
    int (*)(uid_t, uid_t)), "setreuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setregid),
    int (*)(gid_t, gid_t)), "setregid declaration");

struct credential_ids {
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;
    gid_t real_gid;
    gid_t effective_gid;
    gid_t saved_gid;
};

struct credential_result {
    int status;
    int error;
};

typedef int (*credential_case)(const struct credential_ids *before,
    struct credential_result *result);

struct named_credential_case {
    const char *name;
    credential_case call;
};

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static int capture_ids(struct credential_ids *ids)
{
    if (raw_syscall3(SYS_getresuid, (long)&ids->real_uid,
            (long)&ids->effective_uid, (long)&ids->saved_uid) != 0)
        return 0;
    if (raw_syscall3(SYS_getresgid, (long)&ids->real_gid,
            (long)&ids->effective_gid, (long)&ids->saved_gid) != 0)
        return 0;
    return 1;
}

static int ids_unchanged(const struct credential_ids *before,
    const struct credential_ids *after)
{
    return after->real_uid == before->real_uid &&
        after->effective_uid == before->effective_uid &&
        after->saved_uid == before->saved_uid &&
        after->real_gid == before->real_gid &&
        after->effective_gid == before->effective_gid &&
        after->saved_gid == before->saved_gid;
}

static int direct_current_resuid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = ERANGE;
    result->status = setresuid(before->real_uid, before->effective_uid,
        before->saved_uid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_resgid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = ERANGE;
    result->status = setresgid(before->real_gid, before->effective_gid,
        before->saved_gid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_uid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = ERANGE;
    result->status = setuid(before->effective_uid);
    result->error = errno;
    return result->status == 0;
}

static int direct_current_gid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = ERANGE;
    result->status = setgid(before->effective_gid);
    result->error = errno;
    return result->status == 0;
}

static int direct_no_change_resuid(const struct credential_ids *before,
    struct credential_result *result)
{
    (void)before;
    errno = ERANGE;
    result->status = setresuid(UINT32_MAX, UINT32_MAX, UINT32_MAX);
    result->error = errno;
    return result->status == 0;
}

static int direct_no_change_resgid(const struct credential_ids *before,
    struct credential_result *result)
{
    (void)before;
    errno = ERANGE;
    result->status = setresgid(UINT32_MAX, UINT32_MAX, UINT32_MAX);
    result->error = errno;
    return result->status == 0;
}

static int direct_rejected_uid(const struct credential_ids *before,
    struct credential_result *result)
{
    (void)before;
    errno = 0;
    result->status = setuid(UINT32_MAX);
    result->error = errno;
    return result->status == -1 && result->error == EINVAL;
}

static int direct_rejected_gid(const struct credential_ids *before,
    struct credential_result *result)
{
    (void)before;
    errno = 0;
    result->status = setgid(UINT32_MAX);
    result->error = errno;
    return result->status == -1 && result->error == EINVAL;
}

static int direct_rejected_groups(const struct credential_ids *before,
    struct credential_result *result)
{
    gid_t groups[1] = { before->effective_gid };

    errno = 0;
    result->status = setgroups(1, groups);
    result->error = errno;
    return result->status == -1 && result->error == EPERM;
}

static int alias_setreuid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = 0;
    result->status = setreuid((uid_t)-1, before->effective_uid);
    result->error = errno;
    return result->status == 0;
}

static int alias_seteuid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = 0;
    result->status = seteuid(before->effective_uid);
    result->error = errno;
    return result->status == 0;
}

static int alias_setregid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = 0;
    result->status = setregid((gid_t)-1, before->effective_gid);
    result->error = errno;
    return result->status == 0;
}

static int alias_setegid(const struct credential_ids *before,
    struct credential_result *result)
{
    errno = 0;
    result->status = setegid(before->effective_gid);
    result->error = errno;
    return result->status == 0;
}

static void print_case(const char *scenario, const char *name,
    const struct credential_result *result, const struct credential_ids *before,
    const struct credential_ids *after)
{
    printf("credentials-profile %s %s: status=%d errno=%d "
        "before=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu "
        "after=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu ids=unchanged\n",
        scenario, name, result->status, result->error,
        (unsigned long)before->real_uid, (unsigned long)before->effective_uid,
        (unsigned long)before->saved_uid, (unsigned long)before->real_gid,
        (unsigned long)before->effective_gid, (unsigned long)before->saved_gid,
        (unsigned long)after->real_uid, (unsigned long)after->effective_uid,
        (unsigned long)after->saved_uid, (unsigned long)after->real_gid,
        (unsigned long)after->effective_gid, (unsigned long)after->saved_gid);
    fflush(stdout);
}

static int run_private_case(const char *scenario,
    const struct named_credential_case *entry)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        struct credential_ids before = { 0 };
        struct credential_ids after = { 0 };
        struct credential_result result = { -1, 0 };
        int before_ok = capture_ids(&before);
        int call_ok = before_ok && entry->call(&before, &result);
        int after_ok = capture_ids(&after);

        if (before_ok && after_ok)
            print_case(scenario, entry->name, &result, &before, &after);
        _exit(before_ok && call_ok && after_ok && ids_unchanged(&before, &after)
            ? 0 : 1);
    }
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0;
}

static int run_cases(const char *scenario,
    const struct named_credential_case *cases, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (!run_private_case(scenario, &cases[index]))
            return 0;
    return 1;
}

static void print_transition(const char *name, int status, int error)
{
    struct credential_ids ids = { 0 };
    gid_t groups[256] = { 0 };
    long count = raw_syscall3(SYS_getgroups, 256, (long)groups, 0);
    int ok = capture_ids(&ids);

    printf("credentials-transition %s: status=%d errno=%d ids=%d "
        "uid=%lu/%lu/%lu gid=%lu/%lu/%lu groups=%ld:%lu,%lu\n",
        name, status, error, ok, (unsigned long)ids.real_uid,
        (unsigned long)ids.effective_uid, (unsigned long)ids.saved_uid,
        (unsigned long)ids.real_gid, (unsigned long)ids.effective_gid,
        (unsigned long)ids.saved_gid, count,
        (unsigned long)(count > 0 ? groups[0] : 0),
        (unsigned long)(count > 1 ? groups[1] : 0));
    fflush(stdout);
}

/* errno is unspecified after success (musl's rendezvous can leave EAGAIN
 * from its semaphore waits), so it is reported only for a failure. */
#define TRANSITION(name, call) do { \
        int transition_status; \
        errno = ERANGE; \
        transition_status = (call); \
        print_transition((name), transition_status, \
            transition_status == 0 ? 0 : errno); \
    } while (0)

static void transition_groups(void)
{
    static const gid_t groups[2] = { 5, 6 };
    TRANSITION("setgroups-two", setgroups(2, groups));
    TRANSITION("setgroups-empty", setgroups(0, NULL));
}

static void transition_resids(void)
{
    TRANSITION("setresgid-distinct", setresgid(11, 12, 13));
    TRANSITION("setresuid-distinct", setresuid(21, 22, 23));
    TRANSITION("setresuid-saved-effective", setresuid((uid_t)-1, 23, (uid_t)-1));
    TRANSITION("setresuid-unprivileged-real", setresuid(99, (uid_t)-1, (uid_t)-1));
    TRANSITION("setresgid-unprivileged", setresgid(99, (gid_t)-1, (gid_t)-1));
    TRANSITION("setuid-unprivileged-saved", setuid(21));
    TRANSITION("setgroups-unprivileged", setgroups(0, NULL));
}

static void transition_root_ids(void)
{
    TRANSITION("setgid-root", setgid(7));
    TRANSITION("setuid-root", setuid(8));
    TRANSITION("setuid-dropped", setuid(0));
    TRANSITION("setgid-dropped", setgid(0));
}

static int run_transition(void (*transition)(void))
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        transition();
        _exit(0);
    }
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0;
}

/* Workers for the `threads` subcase. Each parks in a different state, is
 * caught there by the rendezvous, and after release reports its own raw
 * kernel IDs. The parking states are a condition wait, a spin on an atomic
 * flag, and a restartable blocking pipe read. */
enum { PARKED_WORKERS = 3 };

struct parked_worker {
    pthread_t thread;
    int index;
    struct credential_ids ids;
    long groups;
    gid_t first_group;
    long read_result;
    char read_byte;
};

static pthread_mutex_t park_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t park_condition = PTHREAD_COND_INITIALIZER;
static int park_open;
static int park_parked;
static int park_released;
static int park_pipe[2] = { -1, -1 };

static void worker_report(struct parked_worker *worker)
{
    gid_t groups[256] = { 0 };
    worker->groups = raw_syscall3(SYS_getgroups, 256, (long)groups, 0);
    worker->first_group = worker->groups > 0 ? groups[0] : 0;
    (void)capture_ids(&worker->ids);
}

static void *parked_worker_main(void *argument)
{
    struct parked_worker *worker = argument;
    worker->read_result = 0;
    if (worker->index == 0) {
        pthread_mutex_lock(&park_mutex);
        ++park_parked;
        while (!park_open)
            pthread_cond_wait(&park_condition, &park_mutex);
        pthread_mutex_unlock(&park_mutex);
    } else if (worker->index == 1) {
        __atomic_add_fetch(&park_parked, 1, __ATOMIC_SEQ_CST);
        while (!__atomic_load_n(&park_released, __ATOMIC_SEQ_CST))
            ;
    } else {
        __atomic_add_fetch(&park_parked, 1, __ATOMIC_SEQ_CST);
        worker->read_result = raw_syscall3(SYS_read, park_pipe[0], (long)&worker->read_byte, 1);
    }
    worker_report(worker);
    return NULL;
}

static struct parked_worker parked[PARKED_WORKERS];

static int park_workers(void)
{
    int index;
    park_open = 0;
    park_parked = 0;
    park_released = 0;
    if (pipe(park_pipe) != 0)
        return 0;
    for (index = 0; index < PARKED_WORKERS; ++index) {
        parked[index].index = index;
        if (pthread_create(&parked[index].thread, NULL, parked_worker_main, &parked[index]) != 0)
            return 0;
    }
    while (__atomic_load_n(&park_parked, __ATOMIC_SEQ_CST) != PARKED_WORKERS)
        ;
    /* Give the reader time to block in the kernel read. */
    (void)usleep(20000);
    return 1;
}

static void print_thread_ids(const char *name, const struct credential_ids *ids,
    long groups, gid_t first_group)
{
    printf("credentials-threads %s: uid=%lu/%lu/%lu gid=%lu/%lu/%lu groups=%ld:%lu\n",
        name, (unsigned long)ids->real_uid, (unsigned long)ids->effective_uid,
        (unsigned long)ids->saved_uid, (unsigned long)ids->real_gid,
        (unsigned long)ids->effective_gid, (unsigned long)ids->saved_gid,
        groups, (unsigned long)first_group);
    fflush(stdout);
}

static void release_and_report_workers(void)
{
    static const char *const names[PARKED_WORKERS] = {
        "worker-condition", "worker-spin", "worker-read",
    };
    struct parked_worker self = { 0 };
    int index;
    pthread_mutex_lock(&park_mutex);
    park_open = 1;
    pthread_cond_broadcast(&park_condition);
    pthread_mutex_unlock(&park_mutex);
    __atomic_store_n(&park_released, 1, __ATOMIC_SEQ_CST);
    (void)raw_syscall3(SYS_write, park_pipe[1], (long)"r", 1);
    for (index = 0; index < PARKED_WORKERS; ++index)
        pthread_join(parked[index].thread, NULL);
    worker_report(&self);
    print_thread_ids("caller-thread", &self.ids, self.groups, self.first_group);
    for (index = 0; index < PARKED_WORKERS; ++index)
        print_thread_ids(names[index], &parked[index].ids, parked[index].groups,
            parked[index].first_group);
    printf("credentials-threads worker-read: read=%ld byte=%c\n",
        parked[2].read_result, parked[2].read_byte ? parked[2].read_byte : '-');
    fflush(stdout);
}

static void threads_all_setters(void)
{
    static const gid_t groups[2] = { 5, 6 };
    TRANSITION("threads-setgroups", setgroups(2, groups));
    TRANSITION("threads-setresgid", setresgid(11, 12, 13));
    TRANSITION("threads-setregid", setregid(14, 15));
    TRANSITION("threads-setegid", setegid(16));
    TRANSITION("threads-setgid", setgid(17));
    TRANSITION("threads-setresuid", setresuid(21, 0, 23));
    TRANSITION("threads-setreuid", setreuid(24, 0));
    TRANSITION("threads-seteuid", seteuid(25));
    TRANSITION("threads-seteuid-restore", seteuid(0));
    TRANSITION("threads-setuid", setuid(26));
}

static void threads_initial_caller(void)
{
    if (!park_workers())
        _exit(2);
    threads_all_setters();
    release_and_report_workers();
}

static void *worker_caller_main(void *argument)
{
    (void)argument;
    threads_all_setters();
    return NULL;
}

static void threads_worker_caller(void)
{
    pthread_t caller;
    if (!park_workers() || pthread_create(&caller, NULL, worker_caller_main, NULL) != 0 ||
        pthread_join(caller, NULL) != 0)
        _exit(2);
    release_and_report_workers();
}

static void threads_aliases(void)
{
    if (!park_workers())
        _exit(2);
    TRANSITION("threads-alias-setegid", setegid(31));
    TRANSITION("threads-alias-seteuid", seteuid(32));
    TRANSITION("threads-alias-seteuid-restore", seteuid(0));
    TRANSITION("threads-alias-setregid", setregid((gid_t)-1, 33));
    TRANSITION("threads-alias-setreuid", setreuid((uid_t)-1, 34));
    release_and_report_workers();
}

static void threads_rejected(void)
{
    if (!park_workers())
        _exit(2);
    TRANSITION("threads-drop", setresuid(41, 42, 43));
    TRANSITION("threads-rejected-setresuid", setresuid(0, 0, 0));
    TRANSITION("threads-rejected-setgroups", setgroups(0, NULL));
    release_and_report_workers();
}

/* After the initial thread calls pthread_exit, a worker's setter still
 * reaches every other live thread. The last thread's return exits 0. */
static void *after_initial_exit_main(void *argument)
{
    (void)argument;
    TRANSITION("threads-after-exit-setresgid", setresgid(51, 52, 53));
    TRANSITION("threads-after-exit-setresuid", setresuid(54, 55, 56));
    release_and_report_workers();
    return NULL;
}

static void threads_after_initial_exit(void)
{
    pthread_t caller;
    if (!park_workers() || pthread_create(&caller, NULL, after_initial_exit_main, NULL) != 0)
        _exit(2);
    pthread_exit(NULL);
}

enum { CHURN_TOGGLES = 400 };
static int churn_stop;
static long churn_created;
static long churn_forks;
static long churn_fork_failures;

static void *churn_short_main(void *argument)
{
    (void)argument;
    return NULL;
}

static void *churn_creator_main(void *argument)
{
    (void)argument;
    while (!__atomic_load_n(&churn_stop, __ATOMIC_SEQ_CST)) {
        pthread_t joined;
        pthread_t detached;
        if (pthread_create(&joined, NULL, churn_short_main, NULL) == 0) {
            pthread_join(joined, NULL);
            ++churn_created;
        }
        if (pthread_create(&detached, NULL, churn_short_main, NULL) == 0) {
            pthread_detach(detached);
            ++churn_created;
        }
    }
    return NULL;
}

static void *churn_fork_main(void *argument)
{
    (void)argument;
    while (!__atomic_load_n(&churn_stop, __ATOMIC_SEQ_CST)) {
        int status = 0;
        pid_t child = (churn_forks & 1) ? _Fork() : fork();
        if (child == 0)
            /* The copy may have the toggled effective ID; its saved root
             * ID restores it before the child's own transitions. */
            _exit(seteuid(0) == 0 && setresgid(61, 62, 63) == 0 &&
                setresuid(64, 65, 66) == 0 ? 0 : 1);
        if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            ++churn_fork_failures;
        ++churn_forks;
    }
    return NULL;
}

/* Targeted-thread operations look their target up while the creator's joins
 * and detaches keep the thread list busy. */
static void *churn_signaler_main(void *argument)
{
    pthread_t target = *(pthread_t *)argument;
    while (!__atomic_load_n(&churn_stop, __ATOMIC_SEQ_CST)) {
        struct sched_param parameter;
        int policy;
        (void)pthread_kill(target, 0);
        (void)pthread_getschedparam(target, &policy, &parameter);
    }
    return NULL;
}

static void threads_churn(void)
{
    pthread_t creator;
    pthread_t forker;
    pthread_t signaler;
    struct credential_ids ids = { 0 };
    int failures = 0;
    int toggle;
    if (pthread_create(&creator, NULL, churn_creator_main, NULL) != 0 ||
        pthread_create(&forker, NULL, churn_fork_main, NULL) != 0 ||
        pthread_create(&signaler, NULL, churn_signaler_main, &forker) != 0)
        _exit(2);
    for (toggle = 0; toggle < CHURN_TOGGLES; ++toggle)
        if (seteuid((toggle & 1) ? 0 : 71) != 0)
            ++failures;
    __atomic_store_n(&churn_stop, 1, __ATOMIC_SEQ_CST);
    pthread_join(signaler, NULL);
    pthread_join(creator, NULL);
    pthread_join(forker, NULL);
    (void)capture_ids(&ids);
    printf("credentials-threads churn: toggles=%d failures=%d threads=%s forks=%s "
        "fork-failures=%ld euid=%lu\n", CHURN_TOGGLES, failures,
        churn_created > 0 ? "created" : "none", churn_forks > 0 ? "forked" : "none",
        churn_fork_failures, (unsigned long)ids.effective_uid);
    fflush(stdout);
}

static int equals(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const struct named_credential_case direct_cases[] = {
        { "setresuid-current", direct_current_resuid },
        { "setresgid-current", direct_current_resgid },
        { "setuid-current", direct_current_uid },
        { "setgid-current", direct_current_gid },
        { "setresuid-all-ones", direct_no_change_resuid },
        { "setresgid-all-ones", direct_no_change_resgid },
        { "setuid-unmapped", direct_rejected_uid },
        { "setgid-unmapped", direct_rejected_gid },
        { "setgroups-current", direct_rejected_groups },
    };
    static const struct named_credential_case alias_cases[] = {
        { "setreuid-current", alias_setreuid },
        { "seteuid-current", alias_seteuid },
        { "setregid-current", alias_setregid },
        { "setegid-current", alias_setegid },
    };

    if (argc != 2)
        return 64;
    if (equals(argv[1], "direct")) {
        if (!run_cases("direct", direct_cases,
                sizeof(direct_cases) / sizeof(*direct_cases)))
            return 1;
        puts("credentials-profile direct: successful-current/no-change/rejected IDs-unchanged");
        return 0;
    }
    if (equals(argv[1], "transitions")) {
        struct credential_ids ids = { 0 };
        if (!capture_ids(&ids) || ids.real_uid != 0 || ids.effective_uid != 0)
            return 4;
        if (!run_transition(transition_groups) || !run_transition(transition_resids) ||
            !run_transition(transition_root_ids))
            return 5;
        puts("credentials-profile transitions: real single-thread ID changes");
        return 0;
    }
    if (equals(argv[1], "threads")) {
        struct credential_ids ids = { 0 };
        if (!capture_ids(&ids) || ids.real_uid != 0 || ids.effective_uid != 0)
            return 6;
        if (!run_transition(threads_initial_caller) ||
            !run_transition(threads_worker_caller) ||
            !run_transition(threads_aliases) ||
            !run_transition(threads_rejected) ||
            !run_transition(threads_after_initial_exit) ||
            !run_transition(threads_churn))
            return 7;
        puts("credentials-profile threads: every thread observes each transition");
        return 0;
    }
    if (equals(argv[1], "aliases")) {
        if (!run_cases("aliases", alias_cases,
                sizeof(alias_cases) / sizeof(*alias_cases)))
            return 2;
        puts("credentials-profile aliases: success IDs-unchanged");
        return 0;
    }
    return 64;
}
