#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* The pinned musl caller-stack algorithm uses separate TLS once TLS/TSD
 * exceeds 2 KiB. Keep that choice deterministic without depending on its
 * private pthread layout or subtracting a guessed TCB size. */
static _Thread_local volatile unsigned char local_tls[8192];
static pthread_t initial_thread;
static uintptr_t initial_stack_top;
static uintptr_t initial_local;
enum { PAGE = 4096, SAVED_ERRNO = 77 };

static void require_at(int condition, const char *expression, int line)
{
    if (!condition) {
        fprintf(stderr, "pthread-getattr:%d: %s (errno=%d)\n", line, expression, errno);
        _Exit(95);
    }
}
#define CHECK(x) require_at(!!(x), #x, __LINE__)

_Static_assert(sizeof(pthread_attr_t) == 56 && _Alignof(pthread_attr_t) == 8,
    "musl x86-64 pthread_attr_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getattr_np),
    int (*)(pthread_t, pthread_attr_t *)), "pthread_getattr_np C declaration");

struct observed {
    uintptr_t base;
    size_t size;
    size_t guard;
    int detached;
    int error;
};

/* This is also the call sequence used by the pinned Rust std Unix
 * stack-overflow owner: get live attrs, get usable stack and guard, destroy. */
static struct observed observe(pthread_t thread)
{
    pthread_attr_t attributes;
    struct observed result;
    void *base = NULL;
    memset(&attributes, 0xa5, sizeof attributes);
    errno = SAVED_ERRNO;
    CHECK(pthread_getattr_np(thread, &attributes) == 0);
    result.error = errno;
    CHECK(pthread_attr_getstack(&attributes, &base, &result.size) == 0);
    CHECK(pthread_attr_getguardsize(&attributes, &result.guard) == 0);
    CHECK(pthread_attr_getdetachstate(&attributes, &result.detached) == 0);
    int inherit = -1, policy = -1, scope = -1;
    struct sched_param parameters;
    CHECK(pthread_attr_getinheritsched(&attributes, &inherit) == 0 && inherit == PTHREAD_INHERIT_SCHED);
    CHECK(pthread_attr_getschedpolicy(&attributes, &policy) == 0 && policy == SCHED_OTHER);
    CHECK(pthread_attr_getscope(&attributes, &scope) == 0 && scope == PTHREAD_SCOPE_SYSTEM);
    CHECK(pthread_attr_getschedparam(&attributes, &parameters) == 0 && parameters.sched_priority == 0);
    uintptr_t words[7];
    memcpy(words, &attributes, sizeof words);
    CHECK(words[5] == 0 && words[6] == 0);
    CHECK(pthread_attr_destroy(&attributes) == 0);
    result.base = (uintptr_t)base;
    CHECK(result.base != 0 && result.size <= UINTPTR_MAX - result.base);
    return result;
}

static void check_initial(uintptr_t local)
{
    struct observed attributes = observe(initial_thread);
    CHECK(attributes.base + attributes.size == initial_stack_top);
    CHECK(attributes.base <= local && local < initial_stack_top);
    CHECK(attributes.base % PAGE == 0 && attributes.size % PAGE == 0);
    CHECK(attributes.guard == 0 && attributes.detached == PTHREAD_CREATE_JOINABLE);
    /* Musl's terminating mremap probe hits the unmapped page below the
     * initial stack. Its successful pthread result still exposes EFAULT. */
    CHECK(attributes.error == EFAULT);
}

static void grow_and_query_initial(void) __attribute__((noinline));
static void grow_and_query_initial(void)
{
    volatile unsigned char growth[64 * PAGE];
    for (size_t index = 0; index < sizeof growth; index += PAGE)
        growth[index] = (unsigned char)index;
    check_initial((uintptr_t)&growth[0]);
    CHECK(growth[sizeof growth - PAGE] == 0);
}

struct round_state {
    atomic_int ready;
    atomic_int release;
    atomic_int finished;
    uintptr_t local;
    struct observed attributes;
    int detach_transition;
};

static void *worker(void *opaque)
{
    struct round_state *state = opaque;
    volatile unsigned char local = 1;
    CHECK(local_tls[0] == 0 && local_tls[sizeof local_tls - 1] == 0);
    local_tls[0] = 19;
    local_tls[sizeof local_tls - 1] = 23;
    check_initial(initial_local);
    state->attributes = observe(pthread_self());
    state->local = (uintptr_t)&local;
    atomic_store(&state->ready, 1);
    while (!atomic_load(&state->release))
        sched_yield();
    if (state->detach_transition) {
        struct observed after = observe(pthread_self());
        CHECK(after.detached == PTHREAD_CREATE_DETACHED);
        CHECK(after.base == state->attributes.base && after.size == state->attributes.size);
    }
    CHECK(local_tls[0] == 19 && local_tls[sizeof local_tls - 1] == 23);
    atomic_store(&state->finished, 1);
    return NULL;
}

static void check_guard(const struct observed *attributes)
{
    unsigned char byte;
    struct iovec local = { &byte, 1 };
    struct iovec remote = { (void *)attributes->base, 1 };
    CHECK(syscall(SYS_process_vm_readv, getpid(), &local, 1UL, &remote, 1UL, 0UL) == 1);
    if (attributes->guard) {
        remote.iov_base = (void *)(attributes->base - 1);
        CHECK(syscall(SYS_process_vm_readv, getpid(), &local, 1UL, &remote, 1UL, 0UL) == -1);
        CHECK(errno == EFAULT);
    }
}

static void run_worker(pthread_attr_t *requested, uintptr_t caller_base,
    size_t caller_size, int initially_detached, int detach_transition)
{
    static struct round_state state;
    memset(&state, 0, sizeof state);
    state.detach_transition = detach_transition;
    size_t requested_size, requested_guard;
    pthread_attr_t defaults;
    CHECK(pthread_attr_init(&defaults) == 0);
    CHECK(pthread_attr_getstacksize(requested ? requested : &defaults, &requested_size) == 0);
    CHECK(pthread_attr_getguardsize(requested ? requested : &defaults, &requested_guard) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, requested, worker, &state) == 0);
    while (!atomic_load(&state.ready))
        sched_yield();
    struct observed attributes = observe(thread);
    CHECK(attributes.base == state.attributes.base && attributes.size == state.attributes.size);
    CHECK(attributes.guard == state.attributes.guard && attributes.detached == initially_detached);
    CHECK(attributes.error == SAVED_ERRNO && state.attributes.error == SAVED_ERRNO);
    CHECK(attributes.base <= state.local && state.local < attributes.base + attributes.size);
    if (caller_base) {
        CHECK(attributes.base == caller_base);
        CHECK(attributes.size == ((caller_base + caller_size) & ~(uintptr_t)15) - caller_base);
        CHECK(attributes.guard == 0);
    } else {
        CHECK(attributes.size >= requested_size && attributes.size < requested_size + PAGE);
        CHECK(attributes.guard == ((requested_guard + PAGE - 1) & ~(size_t)(PAGE - 1)));
        CHECK(attributes.base % PAGE == 0);
        check_guard(&attributes);
    }
    if (detach_transition) {
        CHECK(pthread_detach(thread) == 0);
        struct observed after = observe(thread);
        CHECK(after.detached == PTHREAD_CREATE_DETACHED);
        CHECK(after.base == attributes.base && after.size == attributes.size && after.guard == attributes.guard);
    }
    atomic_store(&state.release, 1);
    while (!atomic_load(&state.finished))
        sched_yield();
    if (!initially_detached && !detach_transition) {
        /* Completed joinable metadata remains mapped until its owning join. */
        struct observed after = observe(thread);
        CHECK(after.base == attributes.base && after.detached == PTHREAD_CREATE_JOINABLE);
        CHECK(pthread_join(thread, NULL) == 0);
    }
    CHECK(local_tls[0] == 7 && local_tls[sizeof local_tls - 1] == 11);
}

static void *fork_worker(void *unused)
{
    (void)unused;
    struct observed before = observe(pthread_self());
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct observed after = observe(pthread_self());
        CHECK(after.base == before.base && after.size == before.size && after.guard == before.guard);
        CHECK(after.detached == before.detached && after.error == SAVED_ERRNO);
        _Exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return NULL;
}

static void filtered_main_probe(void)
{
    /* Linux 5.10 uapi/linux/{filter,seccomp}.h: one narrow kernel fixture,
     * without making those raw kernel headers an installed libc dependency. */
    struct filter_instruction { unsigned short code; unsigned char yes, no; unsigned int value; };
    struct filter_program { unsigned short length; struct filter_instruction *instructions; };
    _Static_assert(sizeof(struct filter_instruction) == 8, "sock_filter byte layout");
    _Static_assert(sizeof(struct filter_program) == 16 && offsetof(struct filter_program, instructions) == 8,
        "x86 sock_fprog byte layout");
    struct filter_instruction instructions[] = {
        { 0x20, 0, 0, 0 }, /* BPF_LD|BPF_W|BPF_ABS: seccomp_data.nr */
        { 0x15, 0, 1, SYS_mremap }, /* BPF_JMP|BPF_JEQ|BPF_K */
        { 0x06, 0, 0, 0x00050000 | EPERM }, /* SECCOMP_RET_ERRNO */
        { 0x06, 0, 0, 0x7fff0000 }, /* SECCOMP_RET_ALLOW */
    };
    struct filter_program filter = { sizeof instructions / sizeof instructions[0], instructions };
    CHECK(syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) == 0);
    CHECK(syscall(SYS_seccomp, 1L /* SECCOMP_SET_MODE_FILTER */, 0L, &filter) == 0);
    struct observed attributes = observe(initial_thread);
    CHECK(attributes.base + attributes.size == initial_stack_top);
    CHECK(attributes.size == PAGE && attributes.error == EPERM);
    CHECK(attributes.guard == 0 && attributes.detached == PTHREAD_CREATE_JOINABLE);
}

int main(int argc, char **argv, char **envp)
{
    alarm(15);
    CHECK(argc == 2);
    initial_thread = pthread_self();
    while (*envp)
        ++envp;
    initial_stack_top = ((uintptr_t)(envp + 1) + PAGE - 1) & ~(uintptr_t)(PAGE - 1);
    volatile unsigned char local = 1;
    initial_local = (uintptr_t)&local;
    if (!strcmp(argv[1], "filtered")) {
        filtered_main_probe();
        puts("pthread_getattr_np filtered probe: ok");
        return 0;
    }
    if (!strcmp(argv[1], "fork")) {
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, fork_worker, NULL) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        puts("pthread_getattr_np adopted stack: ok");
        return 0;
    }
    CHECK(!strcmp(argv[1], "ordinary"));
    check_initial(initial_local);
    grow_and_query_initial();
    local_tls[0] = 7;
    local_tls[sizeof local_tls - 1] = 11;
    run_worker(NULL, 0, 0, PTHREAD_CREATE_JOINABLE, 0);
    pthread_attr_t attributes;
    CHECK(pthread_attr_init(&attributes) == 0);
    CHECK(pthread_attr_setstacksize(&attributes, 73729) == 0);
    CHECK(pthread_attr_setguardsize(&attributes, 1) == 0);
    run_worker(&attributes, 0, 0, PTHREAD_CREATE_JOINABLE, 0);
    CHECK(pthread_attr_setguardsize(&attributes, 0) == 0);
    run_worker(&attributes, 0, 0, PTHREAD_CREATE_JOINABLE, 1);
    CHECK(pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0);
    run_worker(&attributes, 0, 0, PTHREAD_CREATE_DETACHED, 0);
    CHECK(pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE) == 0);
    void *mapping = mmap(NULL, 18 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    uintptr_t base = (uintptr_t)mapping + 3;
    const size_t size = 16 * PAGE + 1;
    CHECK(pthread_attr_setstack(&attributes, (void *)base, size) == 0);
    CHECK(pthread_attr_setguardsize(&attributes, PAGE) == 0);
    run_worker(&attributes, base, size, PTHREAD_CREATE_JOINABLE, 0);
    CHECK(munmap(mapping, 18 * PAGE) == 0);
#ifdef CRABC_OWNED_WITNESS
    /* Defensive rejection is additional owned-runtime behavior; musl's
     * direct pthread dereference makes invalid handles outside its contract. */
    unsigned char before[sizeof attributes];
    memset(&attributes, 0xa5, sizeof attributes);
    memcpy(before, &attributes, sizeof before);
    errno = SAVED_ERRNO;
    CHECK(pthread_getattr_np((pthread_t)(uintptr_t)1, &attributes) == ESRCH);
    CHECK(errno == SAVED_ERRNO && memcmp(before, &attributes, sizeof before) == 0);
#endif
    puts("pthread_getattr_np live stack metadata: ok");
    return 0;
}
