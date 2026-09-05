#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern int *fork_initial_tls(void);
extern void fork_install_hooks(void (*)(int), void (*)(int));
static _Thread_local int executable_tls = 29;
static pthread_key_t key;
static int scenario;
static int child_process;
static int initialized[3];
static int finalized;
static int cleanup_count;
static int destructor_count;
static int expected_finalizers;
static pid_t recursive_child;
static int latch[2];
static atomic_int constructor_entered;
static atomic_int sibling_ready;
static atomic_int sibling_release;
static void *one;
static void *two;
typedef int *(*tls_address)(void);
static tls_address one_tls;
static tls_address two_tls;
static atomic_int finalizer_entered;
static char hooks[5];
static int hook_count;



static void require_at(int condition, const char *expression, int line)
{
    if (!condition) {
        fprintf(stderr, "dynamic-fork:%d: %s (errno=%d)\n", line, expression, errno);
        _Exit(92);
    }
}
#define CHECK(x) require_at(!!(x), #x, __LINE__)

static void before_first(void) { hooks[hook_count++] = 'a'; CHECK(dlopen(NULL, RTLD_NOW) != NULL); }
static void before_second(void) { hooks[hook_count++] = 'b'; }
static void parent_first(void) { hooks[hook_count++] = 'A'; CHECK(dlsym(NULL, "malloc") != NULL); }
static void parent_second(void) { hooks[hook_count++] = 'B'; }
static void child_first(void) {
    hooks[hook_count++] = 'C';
    CHECK(dlsym(NULL, "malloc") != NULL);
    int *clear_child_tid = NULL;
    CHECK(syscall(SYS_prctl, PR_GET_TID_ADDRESS, &clear_child_tid, 0L, 0L, 0L) == 0);
    CHECK(clear_child_tid != NULL);
}
static void child_second(void) { hooks[hook_count++] = 'D'; }

static void check_hooks(pid_t result)
{
    CHECK(hook_count == 4 && !strcmp(hooks, result == 0 ? "baCD" : "baAB"));
}

static void *open_library(const char *name)
{
    void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dynamic-fork: dlopen %s: %s\n", name, dlerror());
        _Exit(93);
    }
    return handle;
}

static void constructor_hook(int tag)
{
    CHECK(tag >= 0 && tag < 3);
    CHECK(++initialized[tag] == 1);
    if (scenario == 2 && tag == 1) {
        two = open_library("./libfork-two.so");
    } else if (scenario == 2 && tag == 2) {
        recursive_child = fork();
        CHECK(recursive_child >= 0);
        check_hooks(recursive_child);
        if (!recursive_child) {
            child_process = 1;
            /* Both recursive constructor visitors belong to this surviving
             * thread. Reopening them must neither wait nor invoke them twice. */
            CHECK(open_library("./libfork-one.so") != NULL);
            CHECK(open_library("./libfork-two.so") != NULL);
        }
    } else if (scenario == 3 && tag == 1) {
        atomic_store(&constructor_entered, 1);
        char byte;
        CHECK(read(latch[0], &byte, 1) == 1 && byte == 'R');
    }
}

static void finalizer_hook(int tag)
{
    CHECK((finalized & (1 << tag)) == 0);
    finalized |= 1 << tag;
    if (tag == 1 && scenario == 5) {
        pid_t child = fork();
        CHECK(child >= 0);
        check_hooks(child);
        if (child) {
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            puts("dynamic fork single-task finalizer: ok");
        }
    }
    if (tag == 1 && scenario == 6) {
        CHECK(write(STDOUT_FILENO, "F", 1) == 1);
        atomic_store(&finalizer_entered, 1);
        char byte;
        CHECK(read(STDIN_FILENO, &byte, 1) == 1 && byte == 'R');
    }
    if (tag == 0) {
        CHECK(finalized == expected_finalizers);
        if (child_process && scenario < 2)
            CHECK(cleanup_count == 1 && destructor_count == 1);
    }
}

static void cleanup(void *value)
{
    CHECK(value == (void *)(uintptr_t)73 && cleanup_count++ == 0);
}

static void destructor(void *value)
{
    CHECK(value == (void *)(uintptr_t)73 && cleanup_count == 1 && destructor_count++ == 0);
}

static void *fresh_worker(void *unused)
{
    (void)unused;
    CHECK(executable_tls == 29 && *fork_initial_tls() == 31);
    CHECK(*one_tls() == 32 && *two_tls() == 33);
    CHECK(pthread_getspecific(key) == NULL);
    executable_tls = 119;
    *fork_initial_tls() = 121;
    *one_tls() = 122;
    *two_tls() = 123;
    return NULL;
}

static void *sibling(void *unused)
{
    (void)unused;
    CHECK(executable_tls == 29 && *fork_initial_tls() == 31 && *one_tls() == 32);
    executable_tls = 219;
    *fork_initial_tls() = 221;
    *one_tls() = 222;
    atomic_store(&sibling_ready, 1);
    while (!atomic_load(&sibling_release)) sched_yield();
    CHECK(executable_tls == 219 && *fork_initial_tls() == 221 && *one_tls() == 222);
    return NULL;
}

static void fork_round(void)
{
    pthread_mutexattr_t mutex_attributes;
    pthread_mutex_t inherited_list;
    CHECK(pthread_mutexattr_init(&mutex_attributes) == 0);
    CHECK(pthread_mutexattr_setrobust(&mutex_attributes, PTHREAD_MUTEX_ROBUST) == 0);
    CHECK(pthread_mutex_init(&inherited_list, &mutex_attributes) == 0);
    CHECK(pthread_mutex_lock(&inherited_list) == 0);
    CHECK(pthread_mutex_unlock(&inherited_list) == 0);
    CHECK(pthread_mutexattr_setpshared(&mutex_attributes, PTHREAD_PROCESS_SHARED) == 0);
    pthread_mutex_t *shared = mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED && pthread_mutex_init(shared, &mutex_attributes) == 0);
    CHECK(pthread_mutexattr_destroy(&mutex_attributes) == 0);
    executable_tls = 49;
    *fork_initial_tls() = 51;
    *one_tls() = 52;
    CHECK(pthread_setspecific(key, (void *)(uintptr_t)73) == 0);
    pthread_attr_t before;
    void *stack_before;
    size_t size_before;
    CHECK(pthread_getattr_np(pthread_self(), &before) == 0);
    CHECK(pthread_attr_getstack(&before, &stack_before, &size_before) == 0);
    uintptr_t canary;
    __asm__ volatile("mov %%fs:40, %0" : "=r"(canary));
#ifdef CRABC_OWNED_WITNESS
    uintptr_t runtime_view, cancellation;
    __asm__ volatile("mov %%fs:24, %0" : "=r"(runtime_view));
    __asm__ volatile("mov %%fs:32, %0" : "=r"(cancellation));
    CHECK(runtime_view != 0 && cancellation != 0);
#endif
    pthread_cleanup_push(cleanup, (void *)(uintptr_t)73);
    pid_t child = fork();
    CHECK(child >= 0);
    check_hooks(child);
    if (!child) {
        child_process = 1;
        CHECK(executable_tls == 49 && *fork_initial_tls() == 51 && *one_tls() == 52);
        CHECK(pthread_getspecific(key) == (void *)(uintptr_t)73);
        uintptr_t inherited_canary;
        __asm__ volatile("mov %%fs:40, %0" : "=r"(inherited_canary));
        CHECK(inherited_canary == canary);
#ifdef CRABC_OWNED_WITNESS
        uintptr_t inherited_view, inherited_cancellation;
        __asm__ volatile("mov %%fs:24, %0" : "=r"(inherited_view));
        __asm__ volatile("mov %%fs:32, %0" : "=r"(inherited_cancellation));
        CHECK(inherited_view == runtime_view && inherited_cancellation == cancellation);
#endif
        pthread_attr_t after;
        void *stack_after;
        size_t size_after;
        CHECK(pthread_getattr_np(pthread_self(), &after) == 0);
        CHECK(pthread_attr_getstack(&after, &stack_after, &size_after) == 0);
        CHECK(stack_after == stack_before && size_after == size_before);
        two = open_library("./libfork-two.so");
        two_tls = (tls_address)dlsym(two, "fork_runtime_tls");
        CHECK(two_tls != NULL && *two_tls() == 33);
        *two_tls() = 53;
        pthread_t fresh;
        CHECK(pthread_create(&fresh, NULL, fresh_worker, NULL) == 0);
        CHECK(pthread_join(fresh, NULL) == 0);
        CHECK(executable_tls == 49 && *fork_initial_tls() == 51 && *one_tls() == 52 && *two_tls() == 53);
        expected_finalizers = 7;
        CHECK(pthread_mutex_lock(shared) == 0);
        // Kernel-only exit forces a fresh postfork robust-list registration;
        // ordinary pthread exit additionally proves the adopted userspace walk.
        if (scenario == 8) _Exit(0);
        pthread_exit(NULL);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(executable_tls == 49 && *fork_initial_tls() == 51 && *one_tls() == 52);
    CHECK(pthread_mutex_lock(shared) == EOWNERDEAD);
    CHECK(pthread_mutex_consistent(shared) == 0);
    CHECK(pthread_mutex_unlock(shared) == 0);
    CHECK(pthread_mutex_destroy(shared) == 0 && munmap(shared, sizeof *shared) == 0);
    CHECK(pthread_mutex_destroy(&inherited_list) == 0);
    CHECK(dlopen("./libfork-two.so", RTLD_NOW | RTLD_NOLOAD) == NULL);
    (void)dlerror();
    pthread_cleanup_pop(0);
    CHECK(pthread_setspecific(key, NULL) == 0);
}

static void *fork_worker(void *unused) { (void)unused; fork_round(); return NULL; }
static void *constructor_worker(void *unused) { (void)unused; one = open_library("./libfork-one.so"); return NULL; }

static atomic_int surviving_child_pid;

static void *surviving_worker(void *unused)
{
    (void)unused;
    CHECK(executable_tls == 29 && *fork_initial_tls() == 31 && *one_tls() == 32);
    executable_tls = 129;
    *fork_initial_tls() = 131;
    *one_tls() = 132;
    printf("%ld\n", (long)getpid());
    CHECK(fflush(stdout) == 0);
    char byte;
    /* The external parent sends this only after observing the adopted
     * initial task's actual kernel zombie state, outside the private chroot. */
    CHECK(read(STDIN_FILENO, &byte, 1) == 1 && byte == 'R');
    CHECK(executable_tls == 129 && *fork_initial_tls() == 131 && *one_tls() == 132);
    two = open_library("./libfork-two.so");
    two_tls = (tls_address)dlsym(two, "fork_runtime_tls");
    CHECK(two_tls != NULL && *two_tls() == 33);
    pthread_t fresh;
    CHECK(pthread_create(&fresh, NULL, fresh_worker, NULL) == 0);
    CHECK(pthread_join(fresh, NULL) == 0);
    expected_finalizers = 7;
    return NULL;
}

static void *fork_and_return(void *unused)
{
    (void)unused;
    pid_t child = fork();
    CHECK(child >= 0);
    check_hooks(child);
    if (!child) {
        child_process = 1;
        pthread_t surviving;
        CHECK(pthread_create(&surviving, NULL, surviving_worker, NULL) == 0);
        /* Returning through the inherited original pthread trampoline must
         * now retire the adopted main task and retain the surviving worker. */
        return NULL;
    }
    atomic_store(&surviving_child_pid, child);
    return NULL;
}

static void deny_fork(void)
{
    /* Linux 5.10 seccomp/filter UAPI, local to this isolated failure fixture. */
    struct instruction { unsigned short code; unsigned char yes, no; unsigned int value; };
    struct program { unsigned short length; struct instruction *instructions; };
    struct instruction instructions[] = {
        { 0x20, 0, 0, 0 }, { 0x15, 0, 1, SYS_fork },
        { 0x06, 0, 0, 0x00050000 | EAGAIN }, { 0x06, 0, 0, 0x7fff0000 },
    };
    struct program filter = { 4, instructions };
    CHECK(syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) == 0);
    CHECK(syscall(SYS_seccomp, 1L, 0L, &filter) == 0);
}

static void *exit_worker(void *unused) { (void)unused; exit(0); }

int main(int argc, char **argv)
{
    alarm(15);
    CHECK(argc == 2);
    fork_install_hooks(constructor_hook, finalizer_hook);
    CHECK(initialized[0] == 1);
    CHECK(pthread_key_create(&key, destructor) == 0);
    CHECK(pthread_atfork(before_first, parent_first, child_first) == 0);
    CHECK(pthread_atfork(before_second, parent_second, child_second) == 0);
    if (!strcmp(argv[1], "worker-survivor")) {
        scenario = 7;
        one = open_library("./libfork-one.so");
        one_tls = (tls_address)dlsym(one, "fork_runtime_tls");
        CHECK(one_tls != NULL);
        expected_finalizers = 3;
        pthread_t caller;
        CHECK(pthread_create(&caller, NULL, fork_and_return, NULL) == 0);
        CHECK(pthread_join(caller, NULL) == 0);
        pid_t child = atomic_load(&surviving_child_pid);
        int status;
        CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        puts("dynamic fork survives adopted main exit: ok");
        return 0;
    }
    if (!strcmp(argv[1], "failure")) {
        scenario = 4;
        one = open_library("./libfork-one.so");
        one_tls = (tls_address)dlsym(one, "fork_runtime_tls");
        CHECK(one_tls != NULL);
        pthread_t live;
        CHECK(pthread_create(&live, NULL, sibling, NULL) == 0);
        while (!atomic_load(&sibling_ready)) sched_yield();
        deny_fork();
        errno = 0;
        CHECK(fork() == -1 && errno == EAGAIN);
        check_hooks(-1);
        two = open_library("./libfork-two.so");
        two_tls = (tls_address)dlsym(two, "fork_runtime_tls");
        CHECK(two_tls != NULL);
        pthread_t fresh;
        CHECK(pthread_create(&fresh, NULL, fresh_worker, NULL) == 0);
        CHECK(pthread_join(fresh, NULL) == 0);
        atomic_store(&sibling_release, 1);
        CHECK(pthread_join(live, NULL) == 0);
        expected_finalizers = 7;
        puts("dynamic fork failure unwinds owners: ok");
        return 0;
    }
    if (!strcmp(argv[1], "finalizer-single") || !strcmp(argv[1], "finalizer-held")) {
        scenario = !strcmp(argv[1], "finalizer-single") ? 5 : 6;
        one = open_library("./libfork-one.so");
        expected_finalizers = 3;
        if (scenario == 5) return 0;
        pthread_t exiting;
        CHECK(pthread_create(&exiting, NULL, exit_worker, NULL) == 0);
        while (!atomic_load(&finalizer_entered)) sched_yield();
        CHECK(write(STDOUT_FILENO, "B", 1) == 1);
        pid_t child = fork();
        /* The external parent releases the held finalizer, whose ordinary
         * process exit must finish without allowing this fork to return. */
        CHECK(write(STDOUT_FILENO, child < 0 ? "E" : child ? "P" : "C", 1) == 1);
        _Exit(94);
    }
    if (!strcmp(argv[1], "recursive")) {
        scenario = 2;
        one = open_library("./libfork-one.so");
        CHECK(initialized[1] == 1 && initialized[2] == 1);
        expected_finalizers = 7;
        if (recursive_child) {
            int status;
            CHECK(waitpid(recursive_child, &status, 0) == recursive_child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            puts("dynamic fork recursive constructors: ok");
        }
        return 0;
    }
    if (!strcmp(argv[1], "abandoned")) {
        scenario = 3;
        CHECK(pipe(latch) == 0);
        pthread_t constructor;
        CHECK(pthread_create(&constructor, NULL, constructor_worker, NULL) == 0);
        while (!atomic_load(&constructor_entered)) sched_yield();
        pid_t child = fork();
        CHECK(child >= 0);
        check_hooks(child);
        if (!child) {
            CHECK(dlopen("./libfork-one.so", RTLD_NOW) == NULL);
            const char *error = dlerror();
            CHECK(error != NULL && strstr(error, "inconsistent") != NULL);
            CHECK(open_library("./libfork-two.so") != NULL);
            /* Musl cannot finalize a constructor owned by a vanished thread.
             * This case proves its queue rejection and exits without fini. */
            _Exit(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(write(latch[1], "R", 1) == 1);
        CHECK(pthread_join(constructor, NULL) == 0);
        expected_finalizers = 3;
        puts("dynamic fork vanished constructor: ok");
        return 0;
    }
    CHECK(!strcmp(argv[1], "main") || !strcmp(argv[1], "worker") ||
        !strcmp(argv[1], "kernel-main") || !strcmp(argv[1], "kernel-worker"));
    if (!strncmp(argv[1], "kernel-", 7)) scenario = 8;
    one = open_library("./libfork-one.so");
    one_tls = (tls_address)dlsym(one, "fork_runtime_tls");
    CHECK(one_tls != NULL);
    expected_finalizers = 3;
    pthread_t live;
    CHECK(pthread_create(&live, NULL, sibling, NULL) == 0);
    while (!atomic_load(&sibling_ready)) sched_yield();
    if (!strcmp(argv[1], "worker") || !strcmp(argv[1], "kernel-worker")) {
        pthread_t caller;
        CHECK(pthread_create(&caller, NULL, fork_worker, NULL) == 0);
        CHECK(pthread_join(caller, NULL) == 0);
    } else {
        fork_round();
    }
    atomic_store(&sibling_release, 1);
    CHECK(pthread_join(live, NULL) == 0);
    puts("dynamic fork TLS and pthread adoption: ok");
    return 0;
}
