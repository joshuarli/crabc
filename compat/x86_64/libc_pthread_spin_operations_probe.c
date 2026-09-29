/* Native Linux/x86-64 pinned-musl/project pthread spin-operation evidence.
 *
 * One project-header body runs against pinned musl and as a freestanding
 * static candidate. A pipe handshake makes the child observe a held lock
 * before the parent publishes data and releases it. Fixture-local raw syscalls
 * own mapping, process lifecycle, the handshake, and the result stream.
 */

#define _GNU_SOURCE 1
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#if defined(CRABC_PTHREAD_SPIN_OPERATIONS_FREESTANDING)
/* The selected candidate has no TLS/errno runtime. This visible fixture word
 * checks that its spin operations leave caller-owned error state unchanged. */
volatile int crabc_spin_fixture_errno;
#undef errno
#define errno crabc_spin_fixture_errno
#endif

typedef int (*pthread_spin_init_signature)(pthread_spinlock_t *, int);
typedef int (*pthread_spin_destroy_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_lock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_trylock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_unlock_signature)(pthread_spinlock_t *);

_Static_assert(sizeof(pthread_spinlock_t) == 4 &&
                   _Alignof(pthread_spinlock_t) == 4,
               "musl x86-64 pthread_spinlock_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_init),
                                             pthread_spin_init_signature),
               "pthread_spin_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_destroy),
                                             pthread_spin_destroy_signature),
               "pthread_spin_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_lock),
                                             pthread_spin_lock_signature),
               "pthread_spin_lock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_trylock),
                                             pthread_spin_trylock_signature),
               "pthread_spin_trylock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_unlock),
                                             pthread_spin_unlock_signature),
               "pthread_spin_unlock declaration");

#define CRABC_EBUSY 16
#define CRABC_ERRNO_SENTINEL E2BIG
#define CRABC_LEFT_GUARD 0x13579bdf
#define CRABC_RIGHT_GUARD 0x2468ace0
#define CRABC_INITIAL_WORD ((pthread_spinlock_t)0x51525354)
#define CRABC_PARENT_VALUE 0x12345678
#define CRABC_CHILD_VALUE 0x23456789

struct guarded_spin {
    int left_guard;
    pthread_spinlock_t spinlock;
    int right_guard;
    int value;
    int child_try_result;
    int child_saw_parent_value;
};

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth)
{
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    register long r9 __asm__("r9") = sixth;
    long result;
    __asm__ volatile ("syscall"
                      : "=a" (result), "+r" (r10), "+r" (r8), "+r" (r9)
                      : "a" (number), "D" (first), "S" (second), "d" (third)
                      : "rcx", "r11", "memory");
    return result;
}

#define RAW0(n) raw_syscall6((n), 0, 0, 0, 0, 0, 0)
#define RAW1(n, a) raw_syscall6((n), (long)(a), 0, 0, 0, 0, 0)
#define RAW2(n, a, b) raw_syscall6((n), (long)(a), (long)(b), 0, 0, 0, 0)
#define RAW3(n, a, b, c) \
    raw_syscall6((n), (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define RAW4(n, a, b, c, d) \
    raw_syscall6((n), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)

static void raw_exit(int status)
{
    (void)RAW1(SYS_exit, status);
    for (;;)
        __asm__ volatile ("pause" : : : "memory");
}

static int guards_intact(const struct guarded_spin *state)
{
    return state->left_guard == CRABC_LEFT_GUARD &&
           state->right_guard == CRABC_RIGHT_GUARD;
}

static int local_transitions(void)
{
    struct guarded_spin state = {
        CRABC_LEFT_GUARD, CRABC_INITIAL_WORD, CRABC_RIGHT_GUARD, 0, 0, 0
    };

    errno = CRABC_ERRNO_SENTINEL;
    if (pthread_spin_init(&state.spinlock, PTHREAD_PROCESS_PRIVATE) != 0 ||
        state.spinlock != 0 || !guards_intact(&state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 1;
    if (pthread_spin_trylock(&state.spinlock) != 0 ||
        state.spinlock != CRABC_EBUSY || !guards_intact(&state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 2;
    if (pthread_spin_trylock(&state.spinlock) != CRABC_EBUSY ||
        state.spinlock != CRABC_EBUSY || !guards_intact(&state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 3;
    if (pthread_spin_unlock(&state.spinlock) != 0 || state.spinlock != 0 ||
        !guards_intact(&state) || errno != CRABC_ERRNO_SENTINEL)
        return 4;
    if (pthread_spin_lock(&state.spinlock) != 0 ||
        state.spinlock != CRABC_EBUSY || !guards_intact(&state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 5;
    if (pthread_spin_unlock(&state.spinlock) != 0 || state.spinlock != 0 ||
        !guards_intact(&state) || errno != CRABC_ERRNO_SENTINEL)
        return 6;
    if (pthread_spin_destroy(&state.spinlock) != 0 || state.spinlock != 0 ||
        !guards_intact(&state) || errno != CRABC_ERRNO_SENTINEL)
        return 7;
    return 0;
}

static int shared_handoff(void)
{
    long mapping = raw_syscall6(SYS_mmap, 0, sizeof(struct guarded_spin),
                                PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    struct guarded_spin *state;
    int pipe_fds[2];
    long child;
    long waited;
    int status = -1;
    char ready = 0;
    int result = 0;

    if (mapping < 0 && mapping >= -4095)
        return 10;
    state = (struct guarded_spin *)mapping;
    state->left_guard = CRABC_LEFT_GUARD;
    state->spinlock = CRABC_INITIAL_WORD;
    state->right_guard = CRABC_RIGHT_GUARD;
    state->value = 0;
    state->child_try_result = -1;
    state->child_saw_parent_value = 0;

    errno = CRABC_ERRNO_SENTINEL;
    if (pthread_spin_init(&state->spinlock, PTHREAD_PROCESS_SHARED) != 0 ||
        state->spinlock != 0 || !guards_intact(state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 11;
    if (pthread_spin_lock(&state->spinlock) != 0 ||
        state->spinlock != CRABC_EBUSY || !guards_intact(state) ||
        errno != CRABC_ERRNO_SENTINEL)
        return 12;
    if (RAW2(SYS_pipe2, pipe_fds, 0) != 0)
        return 13;

    child = RAW0(SYS_fork);
    if (child < 0)
        return 14;
    if (child == 0) {
        int try_result;

        (void)RAW1(SYS_close, pipe_fds[0]);
        try_result = pthread_spin_trylock(&state->spinlock);
        __atomic_store_n(&state->child_try_result, try_result, __ATOMIC_RELEASE);
        if (try_result != CRABC_EBUSY || !guards_intact(state) ||
            errno != CRABC_ERRNO_SENTINEL)
            raw_exit(21);
        ready = 'R';
        if (RAW3(SYS_write, pipe_fds[1], &ready, 1) != 1)
            raw_exit(22);
        (void)RAW1(SYS_close, pipe_fds[1]);
        if (pthread_spin_lock(&state->spinlock) != 0 ||
            errno != CRABC_ERRNO_SENTINEL)
            raw_exit(23);
        if (state->value != CRABC_PARENT_VALUE || !guards_intact(state) ||
            state->spinlock != CRABC_EBUSY) {
            (void)pthread_spin_unlock(&state->spinlock);
            raw_exit(24);
        }
        state->child_saw_parent_value = 1;
        state->value = CRABC_CHILD_VALUE;
        if (pthread_spin_unlock(&state->spinlock) != 0 ||
            state->spinlock != 0 || !guards_intact(state) ||
            errno != CRABC_ERRNO_SENTINEL)
            raw_exit(25);
        raw_exit(0);
    }

    (void)RAW1(SYS_close, pipe_fds[1]);
    if (RAW3(SYS_read, pipe_fds[0], &ready, 1) != 1 || ready != 'R')
        result = 15;
    (void)RAW1(SYS_close, pipe_fds[0]);
    if (__atomic_load_n(&state->child_try_result, __ATOMIC_ACQUIRE) !=
            CRABC_EBUSY ||
        state->spinlock != CRABC_EBUSY || !guards_intact(state) ||
        errno != CRABC_ERRNO_SENTINEL)
        result = 16;
    state->value = CRABC_PARENT_VALUE;
    if (pthread_spin_unlock(&state->spinlock) != 0 ||
        errno != CRABC_ERRNO_SENTINEL)
        result = 17;
    waited = RAW4(SYS_wait4, child, &status, 0, 0);
    if (waited != child || status != 0) {
        result = 18;
    } else if (state->child_saw_parent_value != 1 ||
               state->value != CRABC_CHILD_VALUE || state->spinlock != 0 ||
               !guards_intact(state) || errno != CRABC_ERRNO_SENTINEL) {
        result = 19;
    } else if (pthread_spin_destroy(&state->spinlock) != 0 ||
               state->spinlock != 0 || state->value != CRABC_CHILD_VALUE ||
               !guards_intact(state) || errno != CRABC_ERRNO_SENTINEL) {
        result = 20;
    }
    if (RAW2(SYS_munmap, mapping, sizeof(*state)) != 0)
        result = 26;
    return result;
}

int crabc_x86_64_pthread_spin_operations_probe(void)
{
    static const char success[] =
        "spin local/init/trylock/lock/unlock/destroy errno=stable "
        "shared/busy/handoff/payload/destroy errno=stable\n";
    int result = local_transitions();

    if (result != 0)
        return result;
    result = shared_handoff();
    if (result != 0)
        return result;
    if (RAW3(SYS_write, 1, success, sizeof(success) - 1) !=
        sizeof(success) - 1)
        return 27;
    return 0;
}

#if !defined(CRABC_PTHREAD_SPIN_OPERATIONS_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_spin_operations_probe();
}
#endif
