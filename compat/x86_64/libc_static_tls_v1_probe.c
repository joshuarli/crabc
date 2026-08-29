/* Native Linux/x86-64 Static Initial TLS v1 fixture.
 *
 * The project-header C body runs first against pinned musl and then as a
 * freestanding static candidate.  Its TLS definitions deliberately span two
 * linked C translation units plus crabc-libc's errno slot: initialized data,
 * TBSS, and 4096-byte alignment must all be copied from the final executable
 * PT_TLS template for the main thread and each selected child.  This is a
 * private static-artifact proof, not dynamic TLS, a loader, a CRT, or general
 * pthread support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

_Static_assert(__builtin_types_compatible_p(pthread_t, struct __pthread *),
    "x86 pthread_t remains opaque pointer ABI");

enum {
    initial_tls_initial_value = 0x13579bdf,
    peer_initial_tls_initial_value = 0x2a4b6c7d,
    worker_tls_value = 0x2468ace0,
    worker_peer_tls_value = 0x10293847,
    tls_alignment = 4096,
    SYS_ARCH_PRCTL = 158,
    ARCH_GET_FS = 0x1003,
};

__thread int initial_tls_value = initial_tls_initial_value;
__thread int tbss;
__thread unsigned char high_alignment_initialized[32]
    __attribute__((aligned(4096))) = { 0x71, 0x23, 0x5d };

extern __thread int peer_initial_tls_value;
extern __thread int peer_tbss;
extern __thread unsigned char peer_high_alignment_tbss[32];
extern int *peer_initial_tls_value_location(void);
extern int *peer_tbss_location(void);
extern unsigned char *peer_high_alignment_tbss_location(void);
extern uintptr_t peer_high_alignment_address(void);

struct worker_observation {
    int *errno_location;
    int *initial_location;
    int *tbss_location;
    int *peer_initial_location;
    int *peer_tbss_location;
    unsigned char *high_alignment_location;
    unsigned char *peer_high_alignment_location;
    uintptr_t thread_pointer;
    uintptr_t kernel_thread_pointer;
    int kernel_thread_pointer_status;
    int initial_errno;
    int initial_value;
    int initial_tbss;
    int initial_peer_value;
    int initial_peer_tbss;
    unsigned char initial_high_byte;
    unsigned char initial_peer_high_byte;
};

static uintptr_t current_thread_pointer(void)
{
    uintptr_t value;

    __asm__ volatile("movq %%fs:0, %0" : "=r"(value));
    return value;
}

static int arch_get_fs(uintptr_t *thread_pointer)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_ARCH_PRCTL), "D"((long)ARCH_GET_FS),
          "S"(thread_pointer)
        : "cc", "rcx", "r11", "memory");
    return result == 0 ? 0 : -1;
}

static int main_tls_matches_initial_state(void)
{
    uintptr_t kernel_thread_pointer = 0;

    if (errno != 0 || initial_tls_value != initial_tls_initial_value || tbss != 0 ||
        peer_initial_tls_value != peer_initial_tls_initial_value || peer_tbss != 0)
        return 1;
    if (high_alignment_initialized[0] != 0x71 ||
        peer_high_alignment_tbss[0] != 0)
        return 2;
    if (((uintptr_t)high_alignment_initialized & (tls_alignment - 1)) != 0 ||
        (peer_high_alignment_address() & (tls_alignment - 1)) != 0)
        return 3;
    if (arch_get_fs(&kernel_thread_pointer) != 0 ||
        kernel_thread_pointer == 0 ||
        kernel_thread_pointer != current_thread_pointer())
        return 4;
    return 0;
}

static void *observe_fresh_template(void *opaque)
{
    struct worker_observation *observation = opaque;

    observation->errno_location = __errno_location();
    observation->initial_location = &initial_tls_value;
    observation->tbss_location = &tbss;
    observation->peer_initial_location = peer_initial_tls_value_location();
    observation->peer_tbss_location = peer_tbss_location();
    observation->high_alignment_location = high_alignment_initialized;
    observation->peer_high_alignment_location = peer_high_alignment_tbss_location();
    observation->thread_pointer = current_thread_pointer();
    observation->kernel_thread_pointer_status = arch_get_fs(
        &observation->kernel_thread_pointer);
    observation->initial_errno = errno;
    observation->initial_value = initial_tls_value;
    observation->initial_tbss = tbss;
    observation->initial_peer_value = peer_initial_tls_value;
    observation->initial_peer_tbss = peer_tbss;
    observation->initial_high_byte = high_alignment_initialized[0];
    observation->initial_peer_high_byte = peer_high_alignment_tbss[0];

    errno = E2BIG;
    initial_tls_value = worker_tls_value;
    tbss = worker_tls_value;
    peer_initial_tls_value = worker_peer_tls_value;
    peer_tbss = worker_peer_tls_value;
    high_alignment_initialized[0] = 0x4c;
    peer_high_alignment_tbss[0] = 0x8e;
    return opaque;
}

static int run_worker_round(int *main_errno_location, int *main_initial_location,
    int *main_tbss_location, int *main_peer_initial_location,
    int *main_peer_tbss_location, unsigned char *main_high_alignment_location,
    unsigned char *main_peer_high_alignment_location)
{
    pthread_t thread;
    struct worker_observation observation = { 0 };
    void *result = 0;

    if (pthread_create(&thread, 0, observe_fresh_template, &observation) != 0)
        return 1;
    if (pthread_join(thread, &result) != 0)
        return 2;
    if (result != &observation)
        return 3;
    if (observation.errno_location == 0 ||
        observation.errno_location == main_errno_location ||
        observation.initial_location == main_initial_location ||
        observation.tbss_location == main_tbss_location ||
        observation.peer_initial_location == main_peer_initial_location ||
        observation.peer_tbss_location == main_peer_tbss_location ||
        observation.high_alignment_location == main_high_alignment_location ||
        observation.peer_high_alignment_location == main_peer_high_alignment_location)
        return 4;
    if (observation.kernel_thread_pointer_status != 0 ||
        observation.thread_pointer == 0 ||
        observation.kernel_thread_pointer != observation.thread_pointer ||
        ((uintptr_t)observation.high_alignment_location & (tls_alignment - 1)) != 0 ||
        ((uintptr_t)observation.peer_high_alignment_location & (tls_alignment - 1)) != 0)
        return 5;
    if (observation.initial_errno != 0 ||
        observation.initial_value != initial_tls_initial_value ||
        observation.initial_tbss != 0 ||
        observation.initial_peer_value != peer_initial_tls_initial_value ||
        observation.initial_peer_tbss != 0 ||
        observation.initial_high_byte != 0x71 ||
        observation.initial_peer_high_byte != 0)
        return 6;
    return 0;
}

int crabc_x86_64_static_tls_v1_probe(void)
{
    int *main_errno_location = __errno_location();
    int *main_initial_location = &initial_tls_value;
    int *main_tbss_location = &tbss;
    int *main_peer_initial_location = peer_initial_tls_value_location();
    int *main_peer_tbss_location = peer_tbss_location();
    unsigned char *main_high_alignment_location = high_alignment_initialized;
    unsigned char *main_peer_high_alignment_location = peer_high_alignment_tbss_location();
    int initial_state = main_tls_matches_initial_state();

    if (initial_state != 0)
        return 10 + initial_state;
    if (main_errno_location == 0 || main_initial_location == 0 ||
        main_tbss_location == 0 || main_peer_initial_location == 0 ||
        main_peer_tbss_location == 0 || main_high_alignment_location == 0 ||
        main_peer_high_alignment_location == 0)
        return 20;

    errno = EACCES;
    initial_tls_value = 0x5555aaaa;
    tbss = 0x11112222;
    peer_initial_tls_value = 0x33334444;
    peer_tbss = 0x77778888;
    high_alignment_initialized[0] = 0xaa;
    peer_high_alignment_tbss[0] = 0xbb;

    int first = run_worker_round(main_errno_location, main_initial_location,
        main_tbss_location, main_peer_initial_location, main_peer_tbss_location,
        main_high_alignment_location, main_peer_high_alignment_location);
    if (first != 0)
        return 30 + first;
    if (errno != EACCES || initial_tls_value != 0x5555aaaa ||
        tbss != 0x11112222 || peer_initial_tls_value != 0x33334444 ||
        peer_tbss != 0x77778888 || high_alignment_initialized[0] != 0xaa ||
        peer_high_alignment_tbss[0] != 0xbb)
        return 50;

    int second = run_worker_round(main_errno_location, main_initial_location,
        main_tbss_location, main_peer_initial_location, main_peer_tbss_location,
        main_high_alignment_location, main_peer_high_alignment_location);
    if (second != 0)
        return 60 + second;
    if (errno != EACCES || initial_tls_value != 0x5555aaaa ||
        tbss != 0x11112222 || peer_initial_tls_value != 0x33334444 ||
        peer_tbss != 0x77778888 || high_alignment_initialized[0] != 0xaa ||
        peer_high_alignment_tbss[0] != 0xbb)
        return 80;
    return 0;
}

#ifndef CRABC_STATIC_TLS_V1_FREESTANDING
int main(void)
{
    return crabc_x86_64_static_tls_v1_probe();
}
#endif
