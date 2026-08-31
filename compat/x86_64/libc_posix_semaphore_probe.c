/* Static crabc-libc x86-64 unnamed POSIX-semaphore compatibility fixture.
 *
 * The same project-header C body first runs against pinned musl, then through
 * a true -nostdlib/-static candidate.  Raw mmap/fork/wait/exit plumbing is
 * fixture-local: it only puts one pshared sem_t in MAP_SHARED storage so the
 * selected sem_wait/sem_post futex handoff crosses a child process.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <semaphore.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(sem_t) == 32 && _Alignof(sem_t) == 4,
    "x86 sem_t layout");
_Static_assert(sizeof(((sem_t *)0)->__val) == 32,
    "x86 sem_t word storage");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((sem_t *)0)->__val[0]), volatile int),
    "sem_t word qualification");
#define CRABC_SEMAPHORE_VALUE_MAX 0x7fffffff

typedef int (*sem_init_signature)(sem_t *, int, unsigned);
typedef int (*sem_destroy_signature)(sem_t *);
typedef int (*sem_getvalue_signature)(sem_t *__restrict, int *__restrict);
typedef int (*sem_trywait_signature)(sem_t *);
typedef int (*sem_wait_signature)(sem_t *);
typedef int (*sem_post_signature)(sem_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_init),
    sem_init_signature), "sem_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_destroy),
    sem_destroy_signature), "sem_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_getvalue),
    sem_getvalue_signature), "sem_getvalue declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_trywait),
    sem_trywait_signature), "sem_trywait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_wait),
    sem_wait_signature), "sem_wait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_post),
    sem_post_signature), "sem_post declaration");

struct shared_semaphore_state {
    sem_t semaphore;
    volatile int child_seen_waiter;
    volatile int child_posted;
};

static long raw_syscall0(long number)
{
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "a" (number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long first)
{
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "a" (number), "D" (first)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long first, long second)
{
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "a" (number), "D" (first), "S" (second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long first, long second, long third,
    long fourth)
{
    register long r10 __asm__("r10") = fourth;
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result), "+r" (r10)
        : "a" (number), "D" (first), "S" (second), "d" (third)
        : "rcx", "r11", "memory");
    return result;
}

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

static int raw_is_linux_error(long value)
{
    return value < 0 && value >= -4095;
}

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile ("pause" : : : "memory");
}

static int check_unchanged_words(const sem_t *semaphore, int expected)
{
    int index;

    for (index = 0; index < 8; ++index) {
        if (semaphore->__val[index] != expected)
            return 0;
    }
    return 1;
}

static int check_local_semantics(void)
{
    sem_t semaphore;
    int value;
    int index;

    for (index = 0; index < 8; ++index)
        semaphore.__val[index] = 0x13579bdf;
    errno = E2BIG;
    if (sem_init(&semaphore, 0, 2) != 0 || errno != E2BIG)
        return 10;
    if (semaphore.__val[0] != 2 || semaphore.__val[1] != 0 ||
        semaphore.__val[2] != 128)
        return 11;
    if (sem_getvalue(&semaphore, &value) != 0 || value != 2 || errno != E2BIG)
        return 12;
    if (sem_trywait(&semaphore) != 0 || sem_getvalue(&semaphore, &value) != 0 ||
        value != 1 || errno != E2BIG)
        return 13;
    if (sem_wait(&semaphore) != 0 || sem_getvalue(&semaphore, &value) != 0 ||
        value != 0 || errno != E2BIG)
        return 14;
    if (sem_trywait(&semaphore) != -1 || errno != EAGAIN)
        return 15;
    if (sem_post(&semaphore) != 0 || errno != EAGAIN ||
        sem_getvalue(&semaphore, &value) != 0 || value != 1)
        return 16;
    if (sem_wait(&semaphore) != 0 || errno != EAGAIN)
        return 17;

    if (sem_init(&semaphore, 0, CRABC_SEMAPHORE_VALUE_MAX) != 0)
        return 18;
    errno = E2BIG;
    if (sem_post(&semaphore) != -1 || errno != EOVERFLOW ||
        sem_getvalue(&semaphore, &value) != 0 || value != CRABC_SEMAPHORE_VALUE_MAX)
        return 19;

    for (index = 0; index < 8; ++index)
        semaphore.__val[index] = 0x2468ace0;
    errno = E2BIG;
    if (sem_init(&semaphore, 0, (unsigned)CRABC_SEMAPHORE_VALUE_MAX + 1U) != -1 ||
        errno != EINVAL || !check_unchanged_words(&semaphore, 0x2468ace0))
        return 20;
    if (sem_destroy(&semaphore) != 0 ||
        !check_unchanged_words(&semaphore, 0x2468ace0))
        return 21;
    return 0;
}

static int check_pshared_wait_post(void)
{
    struct shared_semaphore_state *shared;
    long mapping;
    long child;
    long waited;
    int status = -1;
    int value = -1;
    unsigned long spins;

    mapping = raw_syscall6(SYS_mmap, 0, (long)sizeof(*shared),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (raw_is_linux_error(mapping))
        return 30;
    shared = (struct shared_semaphore_state *)(uintptr_t)mapping;
    shared->child_seen_waiter = 0;
    shared->child_posted = 0;
    if (sem_init(&shared->semaphore, 1, 0) != 0 ||
        shared->semaphore.__val[2] != 0) {
        (void)raw_syscall2(SYS_munmap, mapping, (long)sizeof(*shared));
        return 31;
    }

    child = raw_syscall0(SYS_fork);
    if (raw_is_linux_error(child)) {
        (void)raw_syscall2(SYS_munmap, mapping, (long)sizeof(*shared));
        return 32;
    }
    if (child == 0) {
        for (spins = 0; spins < 10000000UL; ++spins) {
            if (shared->semaphore.__val[1] > 0)
                break;
            (void)raw_syscall0(SYS_sched_yield);
        }
        if (shared->semaphore.__val[1] <= 0)
            raw_exit(101);
        shared->child_seen_waiter = 1;
        if (sem_post(&shared->semaphore) != 0)
            raw_exit(102);
        shared->child_posted = 1;
        raw_exit(0);
    }

    errno = E2BIG;
    if (sem_wait(&shared->semaphore) != 0 || errno != EAGAIN) {
        (void)raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
        (void)raw_syscall2(SYS_munmap, mapping, (long)sizeof(*shared));
        return 33;
    }
    waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    if (waited != child || status != 0 || shared->child_seen_waiter != 1 ||
        shared->child_posted != 1)
        return 34;
    if (sem_getvalue(&shared->semaphore, &value) != 0 || value != 0 ||
        sem_destroy(&shared->semaphore) != 0)
        return 35;
    if (raw_syscall2(SYS_munmap, mapping, (long)sizeof(*shared)) != 0)
        return 36;
    return 0;
}

int crabc_x86_64_posix_semaphore_probe(void)
{
    int result;

    if ((result = check_local_semantics()) != 0)
        return result;
    return check_pshared_wait_post();
}

#if !defined(CRABC_POSIX_SEMAPHORE_FREESTANDING)
int main(void)
{
    return crabc_x86_64_posix_semaphore_probe();
}
#endif
